# scripts/lib/exemption-yaml.sh
#
# Generic awk transform engine for guard-locked YAML policy files
# (SPEC-EXEMPTION-EDIT section 4). Sourced by scripts/exemption.sh.
# Covers the fleet's actual YAML shapes: top-level list-of-maps keys
# (quality_exceptions.yaml, banned_words_exceptions.yaml), top-level
# scalar lists (sensitive_files_exceptions.yaml), empty flow lists
# (key: []), inline flow lists (paths: ['a', 'b']), nested block
# lists, and flat/dotted scalar keys (coverage_thresholds.yaml).
#
# Provides:
#   ey_run MODE FILE KEY [SPECFILE] [NEWVAL]
#     MODE    add | remove | exists | block | set | get
#     KEY     top-level list key (list modes) or dotted path (set/get)
#     SPECFILE  tab-separated field specs, one per line:
#                 F\tname\tvalue   scalar field
#                 L\tname\tv1,v2   list field (set-equality on match)
#                 S\t\tvalue       bare scalar list item
#     NEWVAL  replacement scalar for set
#   Stdout: transformed file (add/remove/set), extracted block (block),
#     scalar value (get). exists prints nothing.
#   Exit: 0 ok; 1 not found / parse failure; 2 key missing or set on a
#     block/list key; 3 remove matched nothing; 4 add duplicate.
#
# Known limitations (documented in SPEC-EXEMPTION-EDIT NG-01): no
# flow-list items containing commas, no multi-document streams, no
# anchors. Values are compared after dequoting. Spec values are
# verbatim user input: deqspec strips only surrounding quotes, never
# whitespace (patterns like " -- " are significant).
#
# NOTE: the awk program below is single-quoted in bash; it must never
# contain a literal single-quote character (use sprintf("%c", 39)).
# Emission quoting (yq): values pass through verbatim (numeric and
# boolean scalars keep their YAML type); quoting is applied only when
# the value contains YAML metacharacters or significant whitespace.

ey_run() {
    local mode="$1" file="$2" key="$3" specfile="${4:-}" newval="${5:-}"
    awk -v mode="$mode" -v key="$key" -v specfile="$specfile" -v newval="$newval" '
function lindent(s,   n) { n = 0; while (substr(s, n+1, 1) == " ") n++; return n }
function ltrim(s) { sub(/^[ \t]+/, "", s); return s }
function rtrim(s) { sub(/[ \t]+$/, "", s); return s }
function trim(s) { return rtrim(ltrim(s)) }
function deq(s,   t, dq) {
    t = trim(s)
    dq = sprintf("%c", 34)
    if (length(t) >= 2 && substr(t, 1, 1) == sq && substr(t, length(t), 1) == sq) {
        t = substr(t, 2, length(t) - 2); gsub(sq sq, sq, t)
    } else if (length(t) >= 2 && substr(t, 1, 1) == dq && substr(t, length(t), 1) == dq) {
        t = substr(t, 2, length(t) - 2)
    }
    return t
}
function deqspec(s,   t, dq) {
    t = s
    dq = sprintf("%c", 34)
    if (length(t) >= 2 && substr(t, 1, 1) == sq && substr(t, length(t), 1) == sq) {
        t = substr(t, 2, length(t) - 2); gsub(sq sq, sq, t)
    } else if (length(t) >= 2 && substr(t, 1, 1) == dq && substr(t, length(t), 1) == dq) {
        t = substr(t, 2, length(t) - 2)
    }
    return t
}
function yq(v,   t, dq) {
    dq = sprintf("%c", 34)
    if (v == "" || v ~ /[:#\[\]{},&*!|>%@`$"]/ \
        || index(v, sq) > 0 || v ~ /^[-? \t]/ || v ~ /[ \t]$/) {
        t = v; gsub(sq, sq sq, t); return sq t sq
    }
    return v
}
function split_flow(v, arr,   t, n, i, out, m) {
    t = trim(v)
    if (substr(t, 1, 1) == "[") t = substr(t, 2)
    if (substr(t, length(t), 1) == "]") t = substr(t, 1, length(t) - 1)
    n = split(t, arr, ",")
    m = 0
    for (i = 1; i <= n; i++) {
        arr[i] = deq(arr[i])
        if (arr[i] != "") { m++; out[m] = arr[i] }
    }
    for (i = 1; i <= m; i++) arr[i] = out[i]
    return m
}
function seteq(a, b,   na, nb, i, A, B, sa) {
    na = split(a, A, ","); nb = split(b, B, ",")
    if (na != nb) return 0
    for (i = 1; i <= na; i++) sa[A[i]] = 1
    for (i = 1; i <= nb; i++) if (!(B[i] in sa)) return 0
    return 1
}
function parse_entry(s, e,   i, line, cont, rest, ci, name, val, items, ni, k, acc, cur_list, first) {
    split("", seen_f); split("", seen_l); split("", fval); split("", lval)
    e_scalar = ""; cur_list = ""; first = 1
    for (i = s; i <= e; i++) {
        line = L[i]; cont = trim(line)
        if (cont == "" || substr(cont, 1, 1) == "#") continue
        rest = cont
        if (first) {
            first = 0
            sub(/^-[ ]+/, "", rest)
            if (rest !~ /^[A-Za-z0-9_.-]+[ ]*:/) { e_scalar = deq(rest); continue }
        } else if (rest ~ /^-[ ]+/) {
            if (cur_list != "") {
                sub(/^-[ ]+/, "", rest)
                lval[cur_list] = (lval[cur_list] == "" ? deq(rest) : lval[cur_list] "," deq(rest))
            }
            continue
        }
        if (rest ~ /^[A-Za-z0-9_.-]+[ ]*:/) {
            ci = index(rest, ":")
            name = trim(substr(rest, 1, ci - 1))
            val = trim(substr(rest, ci + 1))
            if (val == "") {
                cur_list = name
                seen_l[name] = 1
                if (!(name in lval)) lval[name] = ""
            } else if (substr(val, 1, 1) == "[") {
                cur_list = ""
                seen_l[name] = 1
                ni = split_flow(val, items)
                acc = ""
                for (k = 1; k <= ni; k++) acc = (acc == "" ? items[k] : acc "," items[k])
                lval[name] = acc
            } else {
                cur_list = ""
                seen_f[name] = 1
                fval[name] = deq(val)
            }
        }
    }
}
function entry_matches(   i, n, v) {
    for (i = 1; i <= nspec; i++) {
        n = spec_name[i]; v = spec_val[i]
        if (spec_kind[i] == "S") {
            if (e_scalar == "" || e_scalar != v) return 0
        } else if (spec_kind[i] == "L") {
            if (!(n in seen_l)) return 0
            if (!seteq(lval[n], v)) return 0
        } else {
            if (!(n in seen_f)) return 0
            if (fval[n] != v) return 0
        }
    }
    return 1
}
function emit_entry(   i, items, ni, k, firstdone) {
    firstdone = 0
    for (i = 1; i <= nspec; i++) {
        if (spec_kind[i] == "S") {
            print "  - " yq(spec_val[i])
            return
        }
        if (spec_kind[i] == "F") {
            print (firstdone ? "    " : "  - ") spec_name[i] ": " yq(spec_val[i])
            firstdone = 1
        } else {
            print (firstdone ? "    " : "  - ") spec_name[i] ":"
            firstdone = 1
            ni = split(spec_val[i], items, ",")
            for (k = 1; k <= ni; k++) print "      - " yq(items[k])
        }
    }
}
BEGIN {
    sq = sprintf("%c", 39)
    nspec = 0
    if (specfile != "") {
        while ((getline l < specfile) > 0) {
            nspec++
            split(l, p, "\t")
            spec_kind[nspec] = p[1]
            spec_name[nspec] = p[2]
            spec_val[nspec] = deqspec(p[3])
        }
        close(specfile)
    }
    if (mode == "set" || mode == "get") nseg = split(key, seg, ".")
    nlines = 0
}
{ L[++nlines] = $0 }
END {
    if (mode == "set" || mode == "get") {
        done = 0; err = 0
        for (i = 1; i <= nlines; i++) {
            line = L[i]; cont = trim(line); ind = lindent(line)
            if (cont == "" || substr(cont, 1, 1) == "#") {
                if (mode == "set") print line
                continue
            }
            if (cont ~ /^[A-Za-z0-9_.-]+[ ]*:/) {
                depth = int(ind / 2)
                ci = index(cont, ":")
                k = trim(substr(cont, 1, ci - 1))
                val = trim(substr(cont, ci + 1))
                if (depth < nseg) path[depth] = k
                if (!done && depth == nseg - 1 && k == seg[nseg]) {
                    ok = 1
                    for (j = 1; j < nseg; j++) if (path[j - 1] != seg[j]) ok = 0
                    if (ok) {
                        if (val == "" || val == "[]" || substr(val, 1, 1) == "[") { err = 2; break }
                        if (mode == "get") { print deq(val); exit 0 }
                        printf "%s%s: %s\n", substr(line, 1, ind), k, yq(newval)
                        done = 1
                        continue
                    }
                }
            }
            if (mode == "set") print line
        }
        if (err != 0) exit err
        if (mode == "get") exit 1
        if (!done) exit 1
        exit 0
    }

    keyidx = 0; rest = ""
    for (i = 1; i <= nlines; i++) {
        line = L[i]; cont = trim(line)
        if (lindent(line) == 0 && cont ~ /^[A-Za-z0-9_.-]+[ ]*:/) {
            ci = index(cont, ":")
            if (trim(substr(cont, 1, ci - 1)) == key) {
                keyidx = i
                rest = trim(substr(cont, ci + 1))
                break
            }
        }
    }
    if (keyidx == 0) exit 2
    if (rest != "" && rest != "[]") exit 2

    regionend = nlines + 1
    for (i = keyidx + 1; i <= nlines; i++) {
        cont = trim(L[i])
        if (cont != "" && substr(cont, 1, 1) != "#" && lindent(L[i]) == 0) {
            regionend = i
            break
        }
    }

    nstart = 0
    for (i = keyidx + 1; i < regionend; i++) {
        cont = trim(L[i])
        if (cont != "" && substr(cont, 1, 1) != "#" \
            && lindent(L[i]) == 2 && cont ~ /^-([ ]|$)/) {
            nstart++
            estart[nstart] = i
        }
    }

    if (mode == "block") {
        for (i = keyidx; i < regionend; i++) print L[i]
        exit 0
    }

    if (mode == "exists" || mode == "remove") {
        removed = 0
        for (e = 1; e <= nstart; e++) {
            s = estart[e]
            eend = (e < nstart ? estart[e + 1] - 1 : regionend - 1)
            parse_entry(s, eend)
            if (entry_matches()) {
                if (mode == "exists") exit 0
                drop[e] = 1
                removed++
            }
        }
        if (mode == "exists") exit 1
        if (removed == 0) exit 3
        for (i = 1; i < keyidx; i++) print L[i]
        if (removed == nstart) {
            print key ": []"
        } else {
            print L[keyidx]
        }
        for (i = keyidx + 1; i < regionend; i++) {
            skip = 0
            for (e = 1; e <= nstart; e++) {
                if (!drop[e]) continue
                s = estart[e]
                eend = (e < nstart ? estart[e + 1] - 1 : regionend - 1)
                if (i >= s && i <= eend) {
                    lastc = s
                    for (j = s; j <= eend; j++) {
                        cc = trim(L[j])
                        if (cc != "" && substr(cc, 1, 1) != "#") lastc = j
                    }
                    if (i <= lastc) skip = 1
                }
            }
            if (!skip) print L[i]
        }
        for (i = regionend; i <= nlines; i++) print L[i]
        exit 0
    }

    if (mode == "add") {
        for (e = 1; e <= nstart; e++) {
            s = estart[e]
            eend = (e < nstart ? estart[e + 1] - 1 : regionend - 1)
            parse_entry(s, eend)
            if (entry_matches()) exit 4
        }
        if (rest == "[]") {
            for (i = 1; i < keyidx; i++) print L[i]
            print key ":"
            emit_entry()
            for (i = keyidx + 1; i <= nlines; i++) print L[i]
            exit 0
        }
        lastc = keyidx
        for (i = keyidx + 1; i < regionend; i++) {
            cc = trim(L[i])
            if (cc != "" && substr(cc, 1, 1) != "#") lastc = i
        }
        for (i = 1; i <= lastc; i++) print L[i]
        emit_entry()
        for (i = lastc + 1; i <= nlines; i++) print L[i]
        exit 0
    }

    exit 1
}
' "$file"
}
