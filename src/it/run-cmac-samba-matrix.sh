#!/usr/bin/env bash
# Copyright (C)2016 - SMBJ Contributors
# Licensed under the Apache License, Version 2.0.
# Adapted from the supplied reference pack's scripts/run-cmac-samba-matrix.sh.
set -euo pipefail
[[ -x src/it/samba-multichannel.sh ]] || { echo 'Run from SMBJ multichannel worktree root' >&2; exit 1; }
evidence=${SMB_MATRIX_EVIDENCE:-.work/cmac-matrix/$(date -u +%Y%m%dT%H%M%SZ)-$$}
[[ ! -e $evidence ]] || { echo "Evidence path already exists: $evidence" >&2; exit 2; }
mkdir -p "$evidence"
evidence=$(cd "$evidence" && pwd)
cat > "$evidence/test-limits.gradle" <<'GRADLE'
allprojects {
    tasks.withType(Test).configureEach {
        maxHeapSize = '256m'
        maxParallelForks = 1
        jvmArgs '-XX:ActiveProcessorCount=2'
    }
}
GRADLE
export SMB_TEST_HOST=localhost SMB_TEST_USERNAME=smbtest SMB_TEST_PASSWORD='TestOnly123!'
export SMB_TEST_DOMAIN=WORKGROUP SMB_TEST_SHARE=share SMB_TEST_SIGNING_ALGORITHM=AES_CMAC
unset SMB_TEST_ENCRYPTION_REQUIRED SMB_TEST_REJECT_BINDING_PORTS
cleanup() { src/it/samba-multichannel.sh down >> "$evidence/cleanup.log" 2>&1 || true; }
trap cleanup EXIT
failed=0
for cfg in 'SMB3_00 SMB_3_0' 'SMB3_02 SMB_3_0_2' 'SMB3_11 SMB_3_1_1'; do
    read -r samba_dialect java_dialect <<< "$cfg"
    export SMB_TEST_DIALECT=$java_dialect
    mkdir -p "$evidence/$java_dialect"
    # Configure peers independently so a failed fixture cannot suppress another peer's evidence.
    for peer in current legacy; do
        run="$evidence/$java_dialect/$peer"
        mkdir -p "$run"
        date -u +%FT%TZ > "$run/started"
        if ! src/it/samba-multichannel.sh up "$samba_dialect" desired "$peer" > "$run/setup.log" 2>&1; then
            echo INFRASTRUCTURE_FAILURE > "$run/status"
            failed=1
        fi
    done
    for peer in current legacy; do
        run="$evidence/$java_dialect/$peer"
        if [[ -f $run/status ]]; then continue; fi
        export SMB_TEST_PORTS=36529 SMB_TEST_OTHER_PORT=36530
        if [[ $peer == legacy ]]; then export SMB_TEST_PORTS=36530 SMB_TEST_OTHER_PORT=36529; fi
        export SMB_TEST_PORT=$SMB_TEST_PORTS SMB_TEST_SECONDARY_PORT=445 SMB_TEST_DIFFERENT_SERVER_PORT=445
        other=current
        if [[ $peer == current ]]; then other=legacy; fi
        export SMB_TEST_SECONDARY_HOST=$(docker inspect "smbj-corrective-$peer" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
        export SMB_TEST_DIFFERENT_SERVER_HOST=$(docker inspect "smbj-corrective-$other" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
        printf 'primary=%s:%s secondary=%s:%s differentServer=%s:%s\n' "$SMB_TEST_HOST" "$SMB_TEST_PORT" "$SMB_TEST_SECONDARY_HOST" "$SMB_TEST_SECONDARY_PORT" "$SMB_TEST_DIFFERENT_SERVER_HOST" "$SMB_TEST_DIFFERENT_SERVER_PORT" > "$run/endpoints.txt"
        date -u +%FT%TZ > "$run/started"
        git rev-parse HEAD HEAD\^\{tree\} > "$run/source.txt"
        git diff --binary HEAD > "$run/working-tree.patch"
        while IFS= read -r -d '' path; do
            git diff --no-index --binary /dev/null "$path" >> "$run/working-tree.patch" || [[ $? == 1 ]]
        done < <(git ls-files --others --exclude-standard -z)
        if ! { docker exec "smbj-corrective-$peer" smbd --version > "$run/server-version.txt" 2>&1 &&
               docker exec "smbj-corrective-$peer" testparm -s > "$run/testparm.txt" 2>&1 &&
               docker inspect "smbj-corrective-$peer" --format '{{.Config.Image}} {{json .NetworkSettings.Ports}}' > "$run/server-identity.txt"; }; then
            echo INFRASTRUCTURE_FAILURE > "$run/status"
            failed=1
            continue
        fi
        # Clear prior task results so a failed build cannot be mistaken for this run's evidence.
        rm -rf build/test-results/integrationTest build/reports/tests/integrationTest
        rc=0
        nice -n 10 ./gradlew --no-daemon --max-workers=1 -I "$evidence/test-limits.gradle" -Dorg.gradle.jvmargs="-Xmx256m -XX:ActiveProcessorCount=2" integrationTest -x buildSambaImage --tests '*BoundChannelsIT' \
            --tests '*MultichannelProtocolIT' --tests '*SingleChannelSigningIT' \
            --tests '*MultichannelMultiEndpointIT' --rerun-tasks > "$run/gradle.log" 2>&1 || rc=$?
        echo "$rc" > "$run/exit-status"
        docker logs --timestamps "smbj-corrective-$peer" > "$run/server.log" 2>&1 || true
        for path in build/test-results/integrationTest build/reports/tests/integrationTest; do
            if [[ -d $path ]]; then cp -a "$path" "$run/$(basename "$(dirname "$path")")"; fi
        done
        date -u +%FT%TZ > "$run/finished"
        # A mandatory skipped case is not a PASS. Unconfigured global-encryption rejection is optional.
        if ! python3 src/it/summarize-cmac-matrix.py "$run"; then
            failed=1
            if [[ ! -f $run/status ]]; then echo FAIL > "$run/status"; fi
        fi
        find "$run" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > "$run/SHA256SUMS"
        cat "$run/status"
    done
    cleanup
done
echo "Evidence: $evidence"
exit "$failed"
