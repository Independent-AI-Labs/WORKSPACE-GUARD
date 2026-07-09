# scripts/lib/binary-lock-yaml.sh
#
# emit_binary_lock: join config/binary-policy-rules.yaml against the GTFOBins
# parse + live surface, emit res/binary-lock.yaml (full GTFOBins coverage with
# per-host contained flags).
#
# SOURCED by scripts/sync-gtfobins. Relies on these globals being set by the
# parent script before calling emit_binary_lock:
#   REPO_ROOT, RES_DIR
#   GTFOS_SUID_TMP, GTFOS_SUDO_TMP, GTFOS_CAPS_TMP, KONS_SUID_TMP
#   SUID_LIVE_TMP, CAPS_LIVE_TMP
#   register_temp(), DEVNULL
#
# Pure bash + awk. No higher-level scripting interpreter is used.

emit_binary_lock() {
    local rules_file="$REPO_ROOT/config/binary-policy-rules.yaml"
    local out="$RES_DIR/binary-lock.yaml"
    if [[ ! -f "$rules_file" ]]; then
        echo "ERROR: $rules_file missing; cannot emit res/binary-lock.yaml" >&2
        return 1
    fi

    # Live-surface index: bname \t path \t has_real (1|0)
    # Built first so live-surface basenames not in GTFOBins (e.g. newuidmap,
    # newgidmap) can be folded into the universe for full coverage.
    local live_tmp
    live_tmp="$(mktemp)"; register_temp "$live_tmp"
    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        local bname has_real=0
        bname="$(basename "$path")"
        [[ -f "${path}.real" ]] && has_real=1
        printf '%s\t%s\t%s\n' "$bname" "$path" "$has_real" >> "$live_tmp"
    done < "$SUID_LIVE_TMP"
    while IFS=$'\t' read -r path caps; do
        [[ -z "$path" ]] && continue
        local bname has_real=0
        bname="$(basename "$path")"
        [[ -f "${path}.real" ]] && has_real=1
        # Skip if already recorded via SUID loop (basename collision).
        if grep -qxP "^$bname\t" "$live_tmp"; then continue; fi
        printf '%s\t%s\t%s\n' "$bname" "$path" "$has_real" >> "$live_tmp"
    done < "$CAPS_LIVE_TMP"

    # Build a flat universe file: bname \t tags (space-joined).
    # Dedup across SUID/sudo/caps/kons lists. Tags are union of which lists
    # named the binary (suid, sudo, caps). Live-surface-only binaries (not in
    # any GTFOBins list) are appended with the tag matching how they were found.
    local universe_tmp
    universe_tmp="$(mktemp)"; register_temp "$universe_tmp"
    {
        awk '{ printf "%s\tsuid\n", $0 }' "$GTFOS_SUID_TMP"
        awk '{ printf "%s\tsudo\n", $0 }' "$GTFOS_SUDO_TMP"
        awk '{ printf "%s\tcaps\n", $0 }' "$GTFOS_CAPS_TMP"
        awk '{ printf "%s\tsuid\n", $0 }' "$KONS_SUID_TMP"
    } | awk -F'\t' '
        {
            b=$1; t=$2
            if (b in seen) {
                all[b] = all[b] " " t
            } else {
                seen[b]=1
                all[b]=t
                order[++n]=b
            }
        }
        END {
            for (i=1;i<=n;i++) {
                b=order[i]
                # dedup tags within space-joined list
                split(all[b], parts, " ")
                out=""
                delete got
                for (j in parts) {
                    tg=parts[j]
                    if (tg=="" || tg in got) continue
                    got[tg]=1
                    if (out!="") out=out " "
                    out=out tg
                }
                print b "\t" out
            }
        }
    ' > "$universe_tmp"
    # Append live-surface basenames absent from GTFOBins, tagged by discovery.
    # Build a bname+tag stream: live SUID entries get "suid", live caps entries
    # get "caps"; dedup and fold any binary not already in the universe.
    local live_tag_tmp
    live_tag_tmp="$(mktemp)"; register_temp "$live_tag_tmp"
    awk 'NF>0 { n=split($0,a,"/"); printf "%s\tsuid\n", a[n] }' "$SUID_LIVE_TMP" > "$live_tag_tmp"
    awk -F'\t' 'NF>0 { n=split($1,a,"/"); printf "%s\tcaps\n", a[n] }' "$CAPS_LIVE_TMP" >> "$live_tag_tmp"
    awk -F'\t' -v univ="$universe_tmp" -v live_tag="$live_tag_tmp" '
        BEGIN {
            while ((getline ln < univ) > 0) {
                split(ln, f, "\t"); seen[f[1]]=1
            }
            close(univ)
            while ((getline ln < live_tag) > 0) {
                split(ln, f, "\t"); bn=f[1]; tg=f[2]
                if (bn in seen) continue
                if (bn in added) {
                    if (index(" " addtag[bn] " ", " " tg " ")==0)
                        addtag[bn] = addtag[bn] " " tg
                } else {
                    added[bn]=1; addtag[bn]=tg; addorder[++m]=bn
                }
            }
            close(live_tag)
            for (i=1;i<=m;i++) {
                b=addorder[i]
                print b "\t" addtag[b]
            }
        }
    ' >> "$universe_tmp"

    # Rules parsed into TSV: ruleidx \t name \t tags \t policy \t allow_sub \t self_uid \t env
    # reject_patterns are serialised into a parallel file keyed by ruleidx.
    # First-match-wins is preserved by the ascending ruleidx order.
    local rules_tmp rejects_tmp
    rules_tmp="$(mktemp)"; register_temp "$rules_tmp"
    rejects_tmp="$(mktemp)"; register_temp "$rejects_tmp"

    awk -v rules_out="$rules_tmp" '
        function trim(s){ sub(/^[ \t]+/,"",s); sub(/[ \t]+$/,"",s); return s }
        function split_tags_raw(s, a,  n,i) {
            gsub(/\[|\]/,"",s)
            n=split(s,a,/,/)
            out=""
            for (i=1;i<=n;i++) {
                t=trim(a[i])
                if (t=="") continue
                if (out!="") out=out " "
                out=out t
            }
            return out
        }
        function split_list_yaml(s,  a,n,i) {
            gsub(/\[|\]/,"",s)
            n=split(s,a,/,/)
            out=""
            for (i=1;i<=n;i++) {
                t=trim(a[i])
                if (t=="") continue
                if (out!="") out=out ", "
                out=out t
            }
            return out
        }
        function append_env(rule, val,   cur) {
            cur=renv[rule]
            if (cur!="") cur=cur ", "
            renv[rule]=cur val
        }
        BEGIN { ruleidx=0; in_env_block=0 }
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        /^[[:space:]]*version:/ { next }
        /^[[:space:]]*rules:/ { next }
        # Only a 2-space-indented "- " starts a new rule block. Nested
        # list entries (6+ spaces: reject_patterns sub-items, block-list
        # env_sanitise items) are handled as continuations below.
        /^  - / {
            ruleidx++
            in_env_block=0
            line=$0
            sub(/^  - /,"",line)
        }
        {
            if ($0 !~ /^  - /) line=$0
            key=line; sub(/[[:space:]]*:.*$/,"",key); key=trim(key)
            val=line; sub(/^[^:]*:[[:space:]]*/,"",val); val=trim(val)
            # Block-list env_sanitise: bare "env_sanitise:" -> collect items.
            if (key=="env_sanitise" && val=="") { in_env_block=1; next }
            if (in_env_block) {
                if (line ~ /^[[:space:]]*-[[:space:]]*/) {
                    sub(/^[[:space:]]*-[[:space:]]*/,"",line)
                    append_env(ruleidx, trim(line))
                    next
                }
                in_env_block=0
            }
            if (key=="name")        { rname[ruleidx]=val }
            else if (key=="tags")   { rtags[ruleidx]=split_tags_raw(val) }
            else if (key=="policy") { rpolicy[ruleidx]=val }
            else if (key=="allow_subcommands") { rsub[ruleidx]=split_list_yaml(val) }
            else if (key=="allow_self_username") { rself[ruleidx]=val }
            else if (key=="env_sanitise") { in_env_block=0; renv[ruleidx]=split_list_yaml(val) }
        }
        END {
            for (i=1;i<=ruleidx;i++) {
                printf "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", i, rname[i], rtags[i], rpolicy[i], rsub[i], rself[i], renv[i] > rules_out
            }
        }
    ' "$rules_file"

    # Join: for each binary in universe, walk rules first-match-wins, emit YAML.
    # Reject patterns are re-read from the rules file in a second awk pass per
    # matched binary to preserve the hand-written YAML verbatim (simpler than
    # serialising them through the TSV).
    awk -F'\t' \
        -v rules_file="$rules_tmp" \
        -v rejects_file="$rules_file" \
        -v live_file="$live_tmp" \
        '
        function trim(s){ sub(/^[ \t]+/,"",s); sub(/[ \t]+$/,"",s); return s }
        function tags_in_set(req, actual,   parts,n,i,tg,ok) {
            if (req=="") return 1
            n=split(req,parts," ")
            for (i=1;i<=n;i++) {
                tg=parts[i]
                if (tg=="") continue
                if (index(" " actual " ", " " tg " ")==0) return 0
            }
            return 1
        }
        function matches_rule(rn, rt, bn, bt) {
            # Exact name match is the most specific matcher: it wins
            # regardless of tags (tags on a name rule are descriptive, not
            # filtering; the universe tags may differ from the rule tags,
            # e.g. sudo is GTFOBins-sudo-tagged but not suid-tagged).
            if (rn!="*" && rn!="") return (rn==bn) ? 1 : 0
            # Tag-only catch-all: name empty or "*". Both need tag subset.
            return tags_in_set(rt, bt)
        }
        function quote_yaml(s) {
            gsub(/\\/, "\\\\", s)
            gsub(/"/, "\\\"", s)
            return "\"" s "\""
        }
        function emit_list(label,str,   parts,n,i,first) {
            n=split(str,parts,/, /)
            printf "    %s: [", label
            first=1
            for (i=1;i<=n;i++) {
                t=trim(parts[i])
                if (t=="") continue
                if (!first) printf ", "
                printf "%s", quote_yaml(t)
                first=0
            }
            printf "]\n"
        }
        BEGIN {
            # Load rules into arrays.
            nrules=0
            while ((getline ln < rules_file) > 0) {
                nrules++
                split(ln, f, "\t")
                rid[nrules]=f[1]
                rname[nrules]=f[2]
                rtags[nrules]=f[3]
                rpol[nrules]=f[4]
                rsub[nrules]=f[5]
                rself[nrules]=f[6]
                renv[nrules]=f[7]
            }
            close(rules_file)

            # Load live-surface by bname (last writer wins, but bnames unique).
            while ((getline ln < live_file) > 0) {
                split(ln, f, "\t")
                lpath[f[1]]=f[2]
                lreal[f[1]]=f[3]+0
            }
            close(live_file)
            # YAML document header (consumed by build.rs BinaryLockFile).
            printf "# Auto-generated by scripts/sync-gtfobins (emit_binary_lock)\n"
            printf "# Do not edit manually; regenerate with: make sync-gtfobins\n"
            printf "# Joins config/binary-policy-rules.yaml against the GTFOBins\n"
            printf "# universe + live SUID/capability surface.\n\n"
            printf "version: 1\n"
            printf "binaries:\n"
        }
        {
            bn=$1; bt=$2
            chosen=0
            for (r=1;r<=nrules;r++) {
                if (matches_rule(rname[r],rtags[r],bn,bt)) { chosen=r; break }
            }
            if (chosen==0) { rpol_v="deny-all-non-root"; rsub_v=""; rself_v="false"; renv_v="LD_PRELOAD, LD_LIBRARY_PATH" }
            else { rpol_v=rpol[chosen]; rsub_v=rsub[chosen]; rself_v=rself[chosen]; renv_v=renv[chosen] }

            # Per-host fields.
            cont="false"; p="null"
            if (bn in lpath) {
                p=quote_yaml(lpath[bn])
                cont=(lreal[bn]==1) ? "true" : "false"
            }

            printf "  - name: %s\n", quote_yaml(bn)
            # tags list
            printf "    tags: ["
            ntags=split(bt, tp, " ")
            first=1
            for (i=1;i<=ntags;i++) {
                if (tp[i]=="") continue
                if (!first) printf ", "
                printf "%s", quote_yaml(tp[i])
                first=0
            }
            printf "]\n"
            printf "    path: %s\n", p
            printf "    contained: %s\n", cont
            printf "    policy: %s\n", rpol_v
            if (rsub_v!="") emit_list("allow_subcommands", rsub_v)
            else printf "    allow_subcommands: []\n"
            if (rself_v=="true") printf "    allow_self_username: true\n"
            else printf "    allow_self_username: false\n"
            if (renv_v!="") emit_list("env_sanitise", renv_v)
            else printf "    env_sanitise: []\n"
            # reject_patterns section is emitted by stream-replaying the rule
            # file blocks; for the initial full-coverage generator we emit the
            # catch-all empty list per row and rely on the build.rs step to
            # read the rule file for the binary-specific reject patterns.
            printf "    reject_patterns: []\n"
            printf "\n"
        }
    ' "$universe_tmp" > "$out"
    echo "    Wrote $out"
}