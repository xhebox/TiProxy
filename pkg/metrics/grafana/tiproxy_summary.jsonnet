// Copyright 2022 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

local grafana = import 'grafonnet/grafana.libsonnet';
local dashboard = grafana.dashboard;
local row = grafana.row;
local graphPanel = grafana.graphPanel;
local prometheus = grafana.prometheus;
local template = grafana.template;

local myNameFlag = 'DS_TEST-CLUSTER';
local myDS = '${' + myNameFlag + '}';

// A new dashboard
local newDash = dashboard.new(
  title='Test-Cluster-TiProxy-Summary',
  editable=true,
  graphTooltip='shared_crosshair',
  refresh='30s',
  time_from='now-1h',
)
.addInput(
  name=myNameFlag,
  label='test-cluster',
  type='datasource',
  pluginId='prometheus',
  pluginName='Prometheus',
)
.addTemplate(
  template.new(
    datasource=myDS,
    hide= 2,
    label='K8s-cluster',
    name='k8s_cluster',
    query='label_values(pd_cluster_status, k8s_cluster)',
    refresh='time',
    sort=1,
  )
)
.addTemplate(
  // Default template for tidb-cloud
  template.new(
    allValues=null,
    current=null,
    datasource=myDS,
    hide='all',
    includeAll=false,
    label='tidb_cluster',
    multi=false,
    name='tidb_cluster',
    query='label_values(pd_cluster_status{k8s_cluster="$kuberentes"}, tidb_cluster)',
    refresh='time',
    regex='',
    sort=1,
    tagValuesQuery='',
  )
).addTemplate(
  // Default template for tidb-cloud
  template.new(
    allValues='.*',
    current=null,
    datasource=myDS,
    hide='',
    includeAll=true,
    label='Instance',
    multi=false,
    name='instance',
    query='label_values(tiproxy_server_connections{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster"}, instance)',
    refresh='load',
    regex='',
    sort=1,
    tagValuesQuery='',
  )
);

// Server row and its panels
local serverRow = row.new(collapse=true, title='Server');
local connectionP = graphPanel.new(
  title='Connection Count',
  datasource=myDS,
  legend_rightSide=true,
  description='TiProxy current connection counts.',
  format='short',
)
.addTarget(
  prometheus.target(
    'tiproxy_server_connections{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}',
    legendFormat='{{instance}}',
  )
)
.addTarget(
  prometheus.target(
    'sum(tiproxy_server_connections{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster"})',
    legendFormat='total',
  )
);

local createConnP = graphPanel.new(
  title='Create Connection OPM',
  datasource=myDS,
  legend_rightSide=true,
  description='TiProxy create connection count per minute.',
  format='short',
)
.addTarget(
  prometheus.target(
    'sum(increase(tiproxy_server_create_connection_total{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (instance)',
    legendFormat='{{instance}}',
  )
);

local disconnP = graphPanel.new(
  title='Disconnection OPM',
  datasource=myDS,
  legend_rightSide=true,
  description='TiProxy disconnection count per minute.',
  format='short',
)
.addTarget(
  prometheus.target(
    'sum(increase(tiproxy_server_disconnection_total{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (type)',
    legendFormat='{{type}}',
  )
);

local goroutineP = graphPanel.new(
  title='Goroutine Count',
  datasource=myDS,
  legend_rightSide=true,
  description='TiProxy current goroutine counts.',
  format='short',
)
.addTarget(
  prometheus.target(
    'go_goroutines{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance", job="tiproxy"}',
    legendFormat='{{instance}}',
  )
)
.addTarget(
  prometheus.target(
    'sum(go_goroutines{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", job="tiproxy"})',
    legendFormat='total',
  )
);

local cpuP = graphPanel.new(
  title='CPU Usage',
  datasource=myDS,
  legend_rightSide=true,
  description='TiProxy CPU usage calculated with process CPU running seconds.',
  format='percentunit',
)
.addTarget(
  prometheus.target(
    'rate(process_cpu_seconds_total{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance", job="tiproxy"}[1m])',
    legendFormat='{{instance}}',
  )
)
.addTarget(
  prometheus.target(
    'tiproxy_server_maxprocs{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance", job="tiproxy"}',
    legendFormat='limit-{{instance}}',
  )
);

local memP = graphPanel.new(
  title='Memory Usage',
  datasource=myDS,
  legend_rightSide=true,
  description='TiProxy process rss memory usage.TiProxy heap memory size in use.',
  format='bytes',
)
.addTarget(
  prometheus.target(
    'process_resident_memory_bytes{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance", job="tiproxy"}',
    legendFormat='process-{{instance}}',
  )
)
.addTarget(
  prometheus.target(
    'go_memory_classes_heap_objects_bytes{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance", job="tiproxy"} + go_memory_classes_heap_unused_bytes{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance", job="tiproxy"}',
    legendFormat='HeapInuse-{{instance}}',
  )
);

local uptimeP = graphPanel.new(
  title='Uptime',
  datasource=myDS,
  legend_rightSide=true,
  format='s',
  description='TiProxy uptime since the last restart.',
)
.addTarget(
  prometheus.target(
    'time() - process_start_time_seconds{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance", job="tiproxy"}',
    legendFormat='{{instance}}',
  )
);

// Query Summary
local queryRow = row.new(collapse=true, title='Query Summary');
local durationP = graphPanel.new(
  title='Duration',
  datasource=myDS,
  legend_rightSide=true,
  description='TiProxy query durations by histogram buckets with different percents.',
  format='s',
)
.addTarget(
  prometheus.target(
    'histogram_quantile(0.99, sum(rate(tiproxy_session_query_duration_seconds_bucket{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (le))',
    legendFormat='99',
  )
)
.addTarget(
  prometheus.target(
    'histogram_quantile(0.95, sum(rate(tiproxy_session_query_duration_seconds_bucket{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (le))',
    legendFormat='95',
  )
)
.addTarget(
  prometheus.target(
    'sum(rate(tiproxy_session_query_duration_seconds_sum{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[30s])) / sum(rate(tiproxy_session_query_duration_seconds_count{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster"}[30s]))',
    legendFormat='avg',
  )
);

local durByInstP = graphPanel.new(
  title='P99 Duration By Instance',
  datasource=myDS,
  legend_rightSide=true,
  description='TiProxy P99 query durations by TiProxy instances.',
  format='s',
)
.addTarget(
  prometheus.target(
    'histogram_quantile(0.99, sum(rate(tiproxy_session_query_duration_seconds_bucket{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (le, instance))',
    legendFormat='{{instance}}',
  )
);

local durByBackP = graphPanel.new(
  title='P99 Duration By Backend',
  datasource=myDS,
  legend_rightSide=true,
  description='TiProxy P99 query durations by backends.',
  format='s',
)
.addTarget(
  prometheus.target(
    'label_replace(histogram_quantile(0.99, sum(rate(tiproxy_session_query_duration_seconds_bucket{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (le, backend)), "backend", "$1", "backend", "(.+-tidb-[0-9]+).*peer.*.svc.*")',
    legendFormat='{{backend}}',
  )
);

local cpsByInstP = graphPanel.new(
  title='CPS by Instance',
  datasource=myDS,
  legend_rightSide=true,
  description='TiProxy query total statistics including both successful and failed ones.',
  format='short',
)
.addTarget(
  prometheus.target(
    'sum(rate(tiproxy_session_query_total{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (instance)',
    legendFormat='{{instance}}',
  )
);

local cpsByBackP = graphPanel.new(
  title='CPS by Backend',
  datasource=myDS,
  legend_rightSide=true,
  description='MySQL command statistics by backends.',
  format='short',
)
.addTarget(
  prometheus.target(
    'label_replace(sum(rate(tiproxy_session_query_total{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (backend), "backend", "$1", "backend", "(.+-tidb-[0-9]+).*peer.*.svc.*")',
    legendFormat='{{backend}}',
  )
);

local cpsByCMDP = graphPanel.new(
  title='CPS by CMD',
  datasource=myDS,
  legend_rightSide=true,
  description='MySQL command statistics by command type',
  format='short',
)
.addTarget(
  prometheus.target(
    'sum(rate(tiproxy_session_query_total{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (cmd_type)',
    legendFormat='{{cmd_type}}',
  )
);

// Balance Summary
local balanceRow = row.new(collapse=true, title='Balance');
local bConnP = graphPanel.new(
  title='Backend Connections',
  datasource=myDS,
  legend_rightSide=true,
  description='Number of connections on all backends.',
  format='short',
)
.addTarget(
  prometheus.target(
    'label_replace(tiproxy_balance_b_conn{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}, "backend", "$1", "backend", "(.+-tidb-[0-9]+).*peer.*.svc.*")',
    legendFormat='{{instance}} | {{backend}}',
  )
);

local bMigCounterP = graphPanel.new(
  title='Session Migration OPM',
  datasource=myDS,
  legend_rightSide=true,
  description='OPM of session migrations on all backends.',
  format='short',
)
.addTarget(
  prometheus.target(
    'label_replace(label_replace(sum(increase(tiproxy_balance_migrate_total{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (migrate_res, from, to), "from", "$1", "from", "(.+-tidb-[0-9]+).*peer.*.svc.*"), "to", "$1", "to", "(.+-tidb-[0-9]+).*peer.*.svc.*")',
    legendFormat='{{migrate_res}}: {{from}} => {{to}}',
  )
);

local bMigDurP = graphPanel.new(
  title='Session Migration Duration',
  datasource=myDS,
  legend_rightSide=true,
  description='Duration of session migrations.',
  format='s',
)
.addTarget(
  prometheus.target(
    'histogram_quantile(0.99, sum(rate(tiproxy_balance_migrate_duration_seconds_bucket{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (le))',
    legendFormat='99',
  )
)
.addTarget(
  prometheus.target(
    'histogram_quantile(0.95, sum(rate(tiproxy_balance_migrate_duration_seconds_bucket{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (le))',
    legendFormat='95',
  )
)
.addTarget(
  prometheus.target(
    'sum(rate(tiproxy_balance_migrate_duration_seconds_sum{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[30s])) / sum(rate(tiproxy_balance_migrate_duration_seconds_count{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster"}[30s]))',
    legendFormat='avg',
  )
);

// Backend Summary
local backendRow = row.new(collapse=true, title='Backend');
local bGetDurP = graphPanel.new(
  title='Get Backend Duration',
  datasource=myDS,
  legend_rightSide=true,
  description='Duration of getting an available backend.',
  format='s',
)
.addTarget(
  prometheus.target(
    'histogram_quantile(0.99, sum(rate(tiproxy_backend_get_backend_duration_seconds_bucket{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (le))',
    legendFormat='99',
  )
)
.addTarget(
  prometheus.target(
    'histogram_quantile(0.95, sum(rate(tiproxy_backend_get_backend_duration_seconds_bucket{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[1m])) by (le))',
    legendFormat='95',
  )
)
.addTarget(
  prometheus.target(
    'sum(rate(tiproxy_backend_get_backend_duration_seconds_sum{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}[30s])) / sum(rate(tiproxy_backend_get_backend_duration_seconds_count{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster"}[30s]))',
    legendFormat='avg',
  )
);

local bPingBeP = graphPanel.new(
  title='Ping Backend Duration',
  datasource=myDS,
  legend_rightSide=true,
  description='Duration of Pinging backends.',
  format='s',
)
.addTarget(
  prometheus.target(
    'label_replace(tiproxy_backend_ping_duration_seconds{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}, "backend", "$1", "backend", "(.+-tidb-[0-9]+).*peer.*.svc.*")',
    legendFormat='{{instance}} | {{backend}}',
  )
);

local bHealthCycleP =
graphPanel.new(
  title='Health Check Cycle',
  datasource=myDS,
  legend_rightSide=true,
  description='Duration of each health check cycle.',
  format='s',
)
.addTarget(
  prometheus.target(
    'tiproxy_backend_health_check_seconds{k8s_cluster="$k8s_cluster", tidb_cluster="$tidb_cluster", instance=~"$instance"}',
    legendFormat='{{instance}}',
  )
);

// Merge together.
local panelW = 12;
local panelH = 6;
local rowW = 24;
local rowH = 1;

local rowPos = {x:0, y:0, w:rowW, h:rowH};
local leftPanelPos = {x:0, y:0, w:panelW, h:panelH};
local rightPanelPos = {x:panelW, y:0, w:panelW, h:panelH};

newDash
.addPanel(
  serverRow
  .addPanel(cpuP, gridPos=leftPanelPos)
  .addPanel(memP, gridPos=rightPanelPos)
  .addPanel(uptimeP, gridPos=leftPanelPos)
  .addPanel(connectionP, gridPos=rightPanelPos)
  .addPanel(createConnP, gridPos=leftPanelPos)
  .addPanel(disconnP, gridPos=rightPanelPos)
  .addPanel(goroutineP, gridPos=leftPanelPos)
  ,
  gridPos=rowPos
)
.addPanel(
  queryRow
  .addPanel(durationP, gridPos=leftPanelPos)
  .addPanel(durByInstP, gridPos=rightPanelPos)
  .addPanel(durByBackP, gridPos=leftPanelPos)
  .addPanel(cpsByInstP, gridPos=rightPanelPos)
  .addPanel(cpsByBackP, gridPos=leftPanelPos)
  .addPanel(cpsByCMDP, gridPos=rightPanelPos)
  ,
  gridPos=rowPos
)
.addPanel(
  balanceRow
  .addPanel(bConnP, gridPos=leftPanelPos)
  .addPanel(bMigCounterP, gridPos=rightPanelPos)
  .addPanel(bMigDurP, gridPos=leftPanelPos)
  ,
  gridPos=rowPos
)
.addPanel(
  backendRow
  .addPanel(bGetDurP, gridPos=leftPanelPos)
  .addPanel(bPingBeP, gridPos=rightPanelPos)
  .addPanel(bHealthCycleP, gridPos=leftPanelPos)
  ,
  gridPos=rowPos
)
