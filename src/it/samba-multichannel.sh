#!/usr/bin/env bash
# Copyright (C)2016 - SMBJ Contributors
# Licensed under the Apache License, Version 2.0.
set -euo pipefail

# Dedicated loopback-only fixtures. No host mounts or persistent test data.
action=${1:-up}
dialect=${2:-SMB3_11}
encryption=${3:-required}
peer=${4:-all}
case "$dialect" in SMB3_11|SMB3_02|SMB3_00) ;; *) exit 2 ;; esac
case "$encryption" in required|desired) ;; *) exit 2 ;; esac
case "$action" in up|down) ;; *) exit 2 ;; esac
case "$peer" in all|current|legacy) ;; *) exit 2 ;; esac
prefix=smbj-corrective
owner=smbj-multichannel-corrective
current=dockurr/samba@sha256:2a0452a12b7a244a22f18d0f233101bb8d4952b5500ae263905e3b9dad3bf2ae
legacy=dperson/samba@sha256:66088b78a19810dd1457a8f39340e95e663c728083efa5fe7dc0d40b2478e869
mkdir -p .work/samba
for version in current legacy; do
    if [ "$peer" != all ] && [ "$peer" != "$version" ]; then continue; fi
    name="$prefix-$version"
    exists=false
    if docker container inspect "$name" >/dev/null 2>&1; then
        exists=true
        label=$(docker container inspect "$name" --format '{{index .Config.Labels "org.smbj.test-owner"}}')
        [ "$label" = "$owner" ] || { echo "Refusing to modify unowned $name" >&2; exit 1; }
    fi
    if [ "$action" = down ]; then
        if [ "$exists" = true ]; then docker rm -f "$name"; fi
        continue
    fi
    path=/shared
    if [ "$version" = legacy ]; then path=/share; fi
    config=".work/samba/$version.conf"
    cat > "$config" <<CONFIG
[global]
 workgroup = WORKGROUP
 security = user
 server min protocol = $dialect
 server max protocol = $dialect
 server multi channel support = yes
 server signing = mandatory
 smb encrypt = desired
 load printers = no
 disable spoolss = yes
 vfs objects =
[share]
 path = $path
 read only = no
 guest ok = no
 valid users = smbtest
 smb encrypt = $encryption
CONFIG
    if [ "$exists" = false ]; then
        if [ "$version" = current ]; then
            docker create --name "$name" --label "org.smbj.test-owner=$owner" --memory 256m --cpus 1 \
                --tmpfs /shared:rw,size=64m,mode=1777 -p 127.0.0.1:36529:445 \
                -e NAME=share -e USER=smbtest -e 'PASS=TestOnly123!' "$current"
            docker cp "$config" "$name:/etc/samba/smb.conf"
            docker start "$name"
        else
            docker run -d --name "$name" --label "org.smbj.test-owner=$owner" --memory 256m --cpus 1 \
                --tmpfs /share:rw,size=64m,mode=1777 -p 127.0.0.1:36530:445 "$legacy" \
                -w WORKGROUP -u 'smbtest;TestOnly123!' -s 'share;/share;yes;no;no;smbtest' -g 'vfs objects = ' -p
        fi
    fi
    # A Docker restart can leave an existing owned fixture stopped.
    docker start "$name" >/dev/null
    started=false
    for attempt in {1..30}; do
        if docker exec "$name" pidof smbd >/dev/null 2>&1; then started=true; break; fi
        sleep 1
    done
    [ "$started" = true ] || { docker logs --tail 30 "$name"; exit 1; }
    docker exec "$name" chmod 1777 "$path"
    docker cp "$config" "$name:/etc/samba/smb.conf"
    ready=false
    for attempt in {1..30}; do
        if docker exec "$name" smbcontrol all reload-config >/dev/null 2>&1; then ready=true; break; fi
        sleep 1
    done
    [ "$ready" = true ] || { docker logs --tail 30 "$name"; exit 1; }
    docker exec "$name" smbd --version
    enabled=$(docker exec "$name" testparm -s --parameter-name='server multi channel support' 2>/dev/null)
    [ "${enabled,,}" = yes ] || { echo "Multichannel is not enabled on $name" >&2; exit 1; }
    actual=$(docker exec "$name" testparm -s --parameter-name='server max protocol' 2>/dev/null)
    expected=$dialect
    if [ "$dialect" = SMB3_11 ] && [ "$actual" = SMB3 ]; then expected=SMB3; fi
    [ "$actual" = "$expected" ] || { echo "Unexpected dialect: $actual" >&2; exit 1; }
    actual=$(docker exec "$name" testparm -s --section-name=share --parameter-name='smb encrypt' 2>/dev/null)
    [ "$actual" = "$encryption" ] || { echo "Unexpected share encryption: $actual" >&2; exit 1; }
    docker exec "$name" testparm -s 2>/dev/null
    docker inspect "$name" --format '{{.Name}} {{.Config.Image}} {{json .NetworkSettings.Ports}}'
done
