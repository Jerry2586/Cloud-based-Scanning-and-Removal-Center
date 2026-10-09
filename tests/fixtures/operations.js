export const revision='a'.repeat(64);
export const operationJob=(state='running')=>({id:'b'.repeat(32),state,action:'ports',started_at:'2026-10-09T01:00:00.000Z',reason:'受控任务',...(state==='running'?{}:{finished_at:'2026-10-09T01:00:01.000Z'})});
export const operationStatus=()=>({schema:'ironcurtain-operations/v1',state:'ready',policy:{revision,tcp:[22,443],udp:[]},job:{state:'idle'},risks:[],sources:{environment:'unavailable',engines:'unavailable',engine_coverage:'0/4',truncated:false},audit:[],quarantine:{state:'empty',items:[],count:0,pending:0}});

export function operationScope(){return {program_roots:['/srv/existing'],business_roots:[],containers:[],discovery:{state:'ready',revision:'b'.repeat(64),observed_at:new Date().toISOString(),count:2,truncated:false,issues:[],candidates:[{id:'1'.repeat(16),kind:'program_roots',value:'/srv/site',origin:'应用目录',enrolled:false},{id:'2'.repeat(16),kind:'containers',value:'app',origin:'容器',enrolled:false}]}};}
