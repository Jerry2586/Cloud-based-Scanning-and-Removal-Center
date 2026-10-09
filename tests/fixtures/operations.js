export const revision='a'.repeat(64);
export const operationJob=(state='running')=>({id:'b'.repeat(32),state,action:'ports',started_at:'2026-10-09T01:00:00.000Z',reason:'受控任务',...(state==='running'?{}:{finished_at:'2026-10-09T01:00:01.000Z'})});
export const operationStatus=()=>({schema:'ironcurtain-operations/v1',state:'ready',policy:{revision,tcp:[22,443],udp:[]},job:{state:'idle'},risks:[],sources:{environment:'unavailable',engines:'unavailable',engine_coverage:'0/4',truncated:false},audit:[],quarantine:{state:'empty',items:[],count:0,pending:0}});
