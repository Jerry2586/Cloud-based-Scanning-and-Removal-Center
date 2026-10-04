#!/usr/bin/env bash
# Fixed image sources only. Never change the host Docker daemon or resolver.
ic_image_network_failure() {
  grep -Eiq 'timeout|timed out|DeadlineExceeded|TLS handshake|no such host|temporary failure|network is unreachable|connection (reset|refused)|unexpected EOF|too many requests|toomanyrequests|(^|[^[:alnum:]])(429|502|503|504)([^[:alnum:]]|$)' "$1"
}
ic_image_matches() {
  local reference=$1 digest=$2 inspection
  inspection=$(docker image inspect --format '{{json .RepoDigests}}' "$reference" 2>/dev/null) || return 1
  python3 -c 'import json,sys; names=json.loads(sys.argv[1]); ref,digest=sys.argv[2:]; repo=ref.split("@")[0].rsplit(":",1)[0]; expected={repo+"@"+digest};
if repo=="docker.io/library/node": expected.update({"node@"+digest,"library/node@"+digest})
assert isinstance(names,list) and any(name in expected for name in names)' "$inspection" "$reference" "$digest" >/dev/null 2>&1
}
ic_image_build() {
  local source=$1 target=$2 log_directory=$3 original digest reference log attempt_log status version
  original=$(sed -n 's/^ARG IRONCURTAIN_NODE_IMAGE=//p' "$source/docker/Dockerfile")
  version=$(jq -er '.node_version' "$source/release-contract.json") || ic_fail '缺少可信 Node 版本'
  [[ $original =~ ^docker.io/library/node:[0-9]+\.[0-9]+\.[0-9]+-bookworm-slim@sha256:[a-f0-9]{64}$ && $original == "docker.io/library/node:$version-bookworm-slim@"* ]] || ic_fail '基础镜像必须与发布合同匹配并固定 SHA-256 摘要'
  digest=${original##*@}
  ic_trusted_dir "$log_directory"
  log=$(mktemp "$log_directory/image-build.XXXXXXXX.log") || ic_fail '无法创建镜像获取日志'
  chmod 600 "$log"
  echo "基础镜像获取记录：$log"
  # The mirror must deliver the same immutable upstream content, including platform manifests.
  for reference in "$original" "m.daocloud.io/$original"; do
    attempt_log=$(mktemp "$log_directory/image-attempt.XXXXXXXX.log") || ic_fail '无法创建镜像检查记录'
    chmod 600 "$attempt_log"
    printf '\n镜像源：%s\n' "$reference" | tee -a "$log"
    if ic_image_matches "$reference" "$digest"; then
      echo '复用摘要一致的本地基础镜像。' | tee -a "$log"
    else
      status=0
      timeout --signal=TERM --kill-after=10s 180s docker pull "$reference" > "$attempt_log" 2>&1 || status=$?
      cat "$attempt_log" | tee -a "$log"
      if (( status != 0 )); then
        if (( status == 124 || status == 137 )) || ic_image_network_failure "$attempt_log"; then
          echo '当前镜像源连接失败，尝试下一固定镜像源。' | tee -a "$log"
          rm -f -- "$attempt_log"
          continue
        fi
        rm -f -- "$attempt_log"
        ic_fail "镜像获取失败；不是可重试的网络错误。请查看 $log"
      fi
      if ! ic_image_matches "$reference" "$digest"; then
        rm -f -- "$attempt_log"
        ic_fail "下载的基础镜像摘要不匹配，拒绝构建。请查看 $log"
      fi
    fi
    status=0
    # Do not repeat an unconditional Hub pull after selecting and verifying a source.
    timeout --signal=TERM --kill-after=10s 300s docker build --pull=false --build-arg "IRONCURTAIN_NODE_IMAGE=$reference" -f "$source/docker/Dockerfile" -t "$target" "$source" > "$attempt_log" 2>&1 || status=$?
    cat "$attempt_log" | tee -a "$log"
    if (( status == 0 )); then
      rm -f -- "$attempt_log"
      echo "镜像构建完成；记录：$log"
      return 0
    fi
    if (( status == 124 || status == 137 )) || ic_image_network_failure "$attempt_log"; then
      echo '构建访问镜像源失败，尝试下一固定镜像源。' | tee -a "$log"
      rm -f -- "$attempt_log"
      continue
    fi
    rm -f -- "$attempt_log"
    ic_fail "程序镜像构建失败，停止安装；请查看 $log"
  done
  ic_fail "官方与备用镜像源均无法完成构建。请检查 DNS、HTTPS 出口和 Docker 代理；日志：$log。现有服务未切换。"
}
