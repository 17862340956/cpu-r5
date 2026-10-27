#!/system/bin/sh
# r5 CPUINFO + verified combo. No unload, mounts or automatic property writes.
REV=qilin-r5-20261028
TARGET=5.15.167-android13-8-o-01144-gb3f32e037fab
FAKE=5.15.167-HUAWEI-Kirin9020
FREQS='307200 441600 556800 672000 787200 902400 1017600 1113600 1228800 1344000 1459200 1555200 1670400 1785600 1900800 2016000 2188800 2323200 2457600 2592000 2707200 2803200 2918400 3000000 3187200'
DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
[ "$(id -u)" = 0 ] || { echo '请选择 ROOT 执行。'; exit 1; }
umask 077
BASE=/data/adb
[ -d "$BASE" ] && [ -w "$BASE" ] || BASE=/data/local/tmp
OUT="$BASE/qilin_r5_$(date '+%Y%m%d_%H%M%S')_$$"
mkdir -p "$OUT/pstore" || exit 1
PASS=0; FAIL=0
say() { printf '%s\n' "$*"; printf '%s\n' "$*" >> "$OUT/run.txt"; }
step() { say "STEP=$1"; printf '%s\n' "$1" > "$OUT/last_step.txt"; sync; }
finish() {
    printf 'pass=%s\nfail=%s\n' "$PASS" "$FAIL" > "$OUT/check_summary.txt"
    dmesg > "$OUT/dmesg_after.txt" 2> "$OUT/dmesg_error.txt"
    grep -iE 'cpuinfo_spoof|CFI failure|CFI check|panic|Oops|Call trace|Unable to handle' "$OUT/dmesg_after.txt" > "$OUT/kernel_hits.txt"
    sync
    if tar -czf "$OUT.tar.gz" -C "$BASE" "${OUT##*/}" 2> "$OUT/archive_error.txt"; then
        say "日志压缩包：$OUT.tar.gz"
    else say "日志目录：$OUT"; fi
}
stop() { say "$1"; finish; exit 1; }
value() { sed -n "s/^$1=//p" "$OUT/status.txt"; }
check() {
    printf '%s=%s\n' "$1" "$2" >> "$OUT/result.txt"
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); say "PASS $1=$2"
    else FAIL=$((FAIL+1)); say "FAIL $1=$2 (expected=$3)"; fi
}
read_check() {
    step "read_$1"
    ACTUAL=$(cat "$2" 2>> "$OUT/read_errors.txt")
    RC=$?
    if [ "$RC" = 0 ]; then check "$1" "$ACTUAL" "$3"
    else FAIL=$((FAIL+1)); say "FAIL read $2 rc=$RC"; fi
}
say "=== CPU r5 组合测试 $REV ==="
say "日志：$OUT"
for FILE in /sys/fs/pstore/*; do
    [ ! -f "$FILE" ] || cat "$FILE" > "$OUT/pstore/${FILE##*/}" 2>> "$OUT/read_errors.txt"
done
[ ! -r /proc/last_kmsg ] || cat /proc/last_kmsg > "$OUT/last_kmsg.txt" 2>> "$OUT/read_errors.txt"
dmesg > "$OUT/dmesg_before.txt" 2> "$OUT/dmesg_error.txt"
cat /proc/modules > "$OUT/modules.txt" 2>> "$OUT/read_errors.txt"
MODE=${1:-}
if [ -z "$MODE" ]; then
    say '1 = 只读预检（默认）；6 = CPUINFO+已验证四分支组合；8 = CPUINFO单项；0 = 状态'
    CHOICE=1
    if [ -t 0 ]; then
        printf '输入编号后回车，直接回车选1：'
        IFS= read -r ANSWER || ANSWER=
        [ -z "$ANSWER" ] || CHOICE=$ANSWER
    fi
    case "$CHOICE" in 1) MODE=inspect ;; 6) MODE=full ;; 8) MODE=cpuinfo ;; 0) MODE=status ;; *) stop '编号无效。' ;; esac
fi
case "$MODE" in inspect|combo|full|cpuinfo|status) : ;; *) stop '支持 inspect、full、combo、cpuinfo、status。' ;; esac
say "选择：$MODE"
LOADED=0
if [ -d /sys/module/cpuinfo_spoof ]; then
    LOADED=1
    cat /proc/cpuinfo_spoof > "$OUT/status.txt" 2>> "$OUT/read_errors.txt"
    cat "$OUT/status.txt"
    [ "$MODE" != status ] || { finish; exit 0; }
    grep -qx "revision=$REV" "$OUT/status.txt" || stop '已有旧版模块，请重启，不自动卸载。'
    grep -qx "stage=$MODE" "$OUT/status.txt" || stop '已有其他项目，切换项目请重启。'
    say '同版本同项目已加载，本次只重复验证，不重新加载。'
fi
[ "$MODE" != status ] || { say '当前未加载模块。'; finish; exit 0; }
if [ "$LOADED" = 0 ]; then
    KO="$DIR/cpuinfo_spoof.ko"; REPORT="$DIR/build_report.json"
    [ -f "$KO" ] && [ -f "$REPORT" ] || stop '请把本SH、新KO、build_report.json一起放到同一个目录。'
    command -v strings >/dev/null 2>&1 || stop '缺少 strings。'
    command -v sha256sum >/dev/null 2>&1 || stop '缺少 sha256sum。'
    strings "$KO" > "$OUT/module_strings.txt"
    grep -qx "version=$REV" "$OUT/module_strings.txt" || stop 'KO不是r5。'
    grep -qx 'name=cpuinfo_spoof' "$OUT/module_strings.txt" || stop '模块名不符。'
    grep -q "^vermagic=$TARGET " "$OUT/module_strings.txt" || stop 'vermagic不符。'
    HASH=$(sha256sum "$KO" | awk '{print $1}')
    EXPECTED=$(awk -F '"' '/"sha256"/ {print $4; exit}' "$REPORT")
    [ -n "$EXPECTED" ] && [ "$HASH" = "$EXPECTED" ] || stop 'KO与构建报告哈希不一致。'
    [ "$(uname -r)" = "$TARGET" ] || stop '当前release与目标不一致。'
    cp "$REPORT" "$OUT/build_report.json"
    printf '%s  %s\n' "$HASH" "$KO" > "$OUT/module_sha256.txt"
    FLAGS="stage=$MODE"
    case "$MODE" in combo|full|cpuinfo) FLAGS="$FLAGS pointer_tests=1" ;; esac
    say "参数：$FLAGS"
    case "$MODE" in full|cpuinfo)
        step open_old_cpuinfo_fd
        exec 9</proc/cpuinfo || stop '打开旧CPUINFO句柄失败。'
        ;;
    esac
    step "before_insmod_$MODE"
    insmod "$KO" $FLAGS > "$OUT/insmod.txt" 2>&1
    RC=$?
    cat "$OUT/insmod.txt"
    say "insmod_exit=$RC"
    [ "$RC" = 0 ] || stop '加载返回错误，保存日志后停止。'
    step "after_insmod_$MODE"
    cat /proc/cpuinfo_spoof > "$OUT/status.txt" 2>> "$OUT/read_errors.txt"
    cat "$OUT/status.txt"
fi
grep -qx "revision=$REV" "$OUT/status.txt" || stop '已加载版本不符。'
if [ "$MODE" = inspect ]; then
    grep -qx 'state=inspect_only' "$OUT/status.txt" || stop '预检状态不符。'
    grep -qx 'applied=0' "$OUT/status.txt" || stop '预检修改数不应大于0。'
    for ITEM in uts cpus topology cpufreq cpuinfo; do
        check "preflight_$ITEM" "$(value preflight_$ITEM)" 0
    done
    say '只读预检结束；未启用伪装。'
    finish
    [ "$FAIL" = 0 ]
    exit $?
fi
grep -qx 'state=active' "$OUT/status.txt" || stop '不是完整active实例，不继续读取。'
grep -qx 'last_error=0' "$OUT/status.txt" || stop '内核报告错误。'
case "$MODE" in
    full) TOTAL=10; POINTERS=9; UTS=1 ;;
    combo) TOTAL=9; POINTERS=8; UTS=1 ;;
    cpuinfo) TOTAL=1; POINTERS=1; UTS=0 ;;
esac
check planned "$(value planned)" "$TOTAL"
check applied "$(value applied)" "$TOTAL"
check pointer_applied "$(value pointer_applied)" "$POINTERS"
check uts_applied "$(value uts_applied)" "$UTS"
[ "$FAIL" = 0 ] || stop '修改计数未达标。'
case "$MODE" in full|cpuinfo)
    check cpuinfo_status "$(value cpuinfo)" pde_pointer_active
    if [ "$LOADED" = 0 ]; then
        step read_old_cpuinfo_fd
        cat <&9 > "$OUT/cpuinfo_old_fd.txt" 2>> "$OUT/read_errors.txt"
        RC=$?
        exec 9<&-
        check old_fd_read_rc "$RC" 0
        # Existing descriptors retain the original seq table; record rather
        # than assume every original CPU view must be identical across ROMs.
        say "旧句柄processor数：$(grep -c '^processor' "$OUT/cpuinfo_old_fd.txt")"
    fi
    step read_cpuinfo_baseline
    cat /proc/cpuinfo > "$OUT/cpuinfo_new.txt" 2>> "$OUT/read_errors.txt" || stop '新CPUINFO读取失败。'
    check processor_count "$(grep -c '^processor' "$OUT/cpuinfo_new.txt")" 12
    check implementer_count "$(grep -c '^CPU implementer[[:space:]]*: 0x48$' "$OUT/cpuinfo_new.txt")" 12
    check hardware "$(sed -n 's/^Hardware[[:space:]]*: //p' "$OUT/cpuinfo_new.txt")" 'HUAWEI Kirin9020'
    for TOOL in dd cmp; do command -v "$TOOL" >/dev/null 2>&1 || stop "缺少$TOOL，保留日志后停止。"; done
    step read_cpuinfo_short_chunks
    exec 8</proc/cpuinfo || stop '短读取测试打开失败。'
    ( dd bs=1 count=1 && dd bs=7 count=1 && dd bs=4096 count=1 && cat ) <&8 > "$OUT/cpuinfo_chunks.txt" 2> "$OUT/short_read_errors.txt"
    SHORT_RC=$?
    check cpuinfo_short_read_rc "$SHORT_RC" 0
    cat <&8 > "$OUT/cpuinfo_after_eof.txt" 2>> "$OUT/read_errors.txt"
    EOF_RC=$?
    check cpuinfo_eof_read_rc "$EOF_RC" 0
    exec 8<&-
    if cmp -s "$OUT/cpuinfo_new.txt" "$OUT/cpuinfo_chunks.txt"; then check cpuinfo_short_read match match
    else check cpuinfo_short_read mismatch match; fi
    check cpuinfo_eof_bytes "$(wc -c < "$OUT/cpuinfo_after_eof.txt" | tr -d ' ')" 0
    [ "$FAIL" = 0 ] || stop 'CPUINFO新增路径验证有失败，停止进一步读取。'
    ;;
esac
ROUND=1
while [ "$ROUND" -le 3 ]; do
    say "=== 读取轮次 $ROUND/3 ==="
    step "before_round_$ROUND"
    case "$MODE" in full|combo)
    check uname_release "$(uname -r)" "$FAKE"
    step read_proc_version
    VERSION=$(cat /proc/version 2>> "$OUT/read_errors.txt")
    printf 'proc_version=%s\n' "$VERSION" >> "$OUT/result.txt"
    case "$VERSION" in "Linux version $FAKE "*) check proc_version_release match match ;;
        *) check proc_version_release mismatch match ;; esac
    for KEY in online possible present; do
        read_check "cpus_$KEY" "/sys/devices/system/cpu/$KEY" '0-11'
    done
    for CPU in 0 1 2 3 4 5 6 7; do
        if [ "$CPU" -lt 4 ]; then CORE=$CPU; PACKAGE=0
        else CORE=$((CPU-4)); PACKAGE=1; fi
        read_check "cpu${CPU}_core_id" "/sys/devices/system/cpu/cpu$CPU/topology/core_id" "$CORE"
        read_check "cpu${CPU}_package" "/sys/devices/system/cpu/cpu$CPU/topology/physical_package_id" "$PACKAGE"
        read_check "cpu${CPU}_die" "/sys/devices/system/cpu/cpu$CPU/topology/die_id" '-1'
    done
    read_check available_frequencies /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies "$FREQS"
    read_check boost_frequencies /sys/devices/system/cpu/cpu0/cpufreq/scaling_boost_frequencies '3187200'
    ;;
    esac
    case "$MODE" in full|cpuinfo)
        step "cpuinfo_repeat_$ROUND"
        cat /proc/cpuinfo > "$OUT/cpuinfo_round_$ROUND.txt" 2>> "$OUT/read_errors.txt"
        if cmp -s "$OUT/cpuinfo_new.txt" "$OUT/cpuinfo_round_$ROUND.txt"; then
            check "cpuinfo_round_$ROUND" match match
        else check "cpuinfo_round_$ROUND" mismatch match; fi
        ;;
    esac
    step "after_round_$ROUND"
    [ "$FAIL" = 0 ] || break
    ROUND=$((ROUND+1))
    [ "$ROUND" -gt 3 ] || sleep 2
done
say "PASS=$PASS FAIL=$FAIL（有限读取测试，不代表长期稳定）"
say 'CPUINFO仅改PDE数据指针；不生成cpu8-11、不挂载、不联动GPU、不启用nproc。'
finish
[ "$FAIL" = 0 ]
