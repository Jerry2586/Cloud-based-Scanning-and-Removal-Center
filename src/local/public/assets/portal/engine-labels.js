// Product-facing vocabulary only; raw engine IDs and exported evidence are unchanged.
export const CAPABILITY_NAMES = Object.freeze({clamav:'文件查杀',trivy:'镜像漏洞',osquery:'端口资产',falco:'行为事件'});
export function engineDisplayText(value) {
 return String(value ?? '').replace(/\bClamAV\b/gi,'文件查杀组件').replace(/\bTrivy\b/gi,'镜像检测组件').replace(/\bOsquery\b/gi,'资产采集组件').replace(/\bFalco\b/gi,'行为监测组件');
}
