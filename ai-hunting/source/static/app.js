const $ = id => document.getElementById(id);

// Dùng textContent để dữ liệu alert không được diễn dịch thành HTML.
const node = (tag, text, parent, className) => {
  const element = document.createElement(tag);
  if (text !== undefined)
    element.textContent = text;
  if (className)
    element.className = className;
  if (parent)
    parent.append(element);
  return element;
};

let dataset;
let ready = false;
let view = 'alerts';
let selectedCase = null;
let rawAlert;

// Phân trang giữ một cửa sổ thời gian cố định; version bỏ qua response tìm kiếm cũ.
let alertOffset = 0;
let alertTotal = 0;
let alertVersion = 0;
let explorerWindow = null;

const cases = [];

// Chỉ giữ cache DOM của case đang hiển thị; bằng chứng gốc vẫn nằm trong record.result.
const caseView = { record: null, result: null, toolCount: 0 };

const examples = {
  host: 'Review security and operational issues on the selected agents within the selected time range. Investigate relevant alert categories, prioritize important signals, and distinguish suspicious from routine activity. Build a UTC timeline with exact alert IDs and state coverage gaps.',
  brute: 'Investigate brute-force activity in the selected scope. Check successful logins and nearby file changes. Consider benign explanations, build a timeline, and cite alert IDs.',
  ps: 'Investigate suspicious PowerShell in the selected scope. Check nearby logins and file changes. Distinguish indicators from evidence of compromise and cite alert IDs.',
  file: 'Investigate file changes in the selected scope. Read syscheck details, correlate available process and authentication context, and build a timeline with exact alert IDs.',
  normal: 'Assess whether activity in the selected scope is consistent with routine use. Inspect supporting context, cite alert IDs, and state any missing evidence of authorization.'
};

// Abort chỉ dừng chờ HTTP; job điều tra trên server vẫn chạy độc lập.
async function api(path, options) {
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), path === '/api/status' ? 90000 : 20000);
  try {
    let response;
    try {
      response = await fetch(path, { ...options, cache: 'no-store', signal: controller.signal });
    } catch (_) {
      const error = Error('Cannot reach the app. Make sure python app.py is running, then reconnect.');
      error.status = 0;
      throw error;
    }
    let data;
    try {
      data = await response.json();
    } catch (_) {
      const error = Error('The app returned an incomplete response. Reconnect to retrieve the saved progress.');
      error.status = 0;
      throw error;
    }
    if (!response.ok) {
      const error = Error(data.error || 'Request failed (HTTP ' + response.status + ').');
      error.status = response.status;
      throw error;
    }
    return data;
  } finally {
    clearTimeout(deadline);
  }
}

function showView(name, caseId = null) {
  view = name;
  selectedCase = caseId;
  for (const key of ['alerts', 'cases']) {
    $('view-' + key).hidden = key !== name;
    if (key === name)
      $('nav-' + key).setAttribute('aria-current', 'page');
    else
      $('nav-' + key).removeAttribute('aria-current');
  }
  $('page-title').textContent = name === 'alerts' ? 'ALERT EXPLORER' : 'INVESTIGATIONS';
  $('page-error').textContent = '';
  if (name === 'cases')
    renderCases();
}

function tab(name, focus = false) {
  for (const key of ['report', 'tools']) {
    const selected = key === name;
    $('tab-' + key).setAttribute('aria-selected', String(selected));
    $('tab-' + key).tabIndex = selected ? 0 : -1;
    $('panel-' + key).hidden = !selected;
  }
  if (focus)
    $('tab-' + name).focus();
}

for (const [index, name] of ['report', 'tools'].entries()) {
  $('tab-' + name).onclick = () => tab(name);
  $('tab-' + name).onkeydown = event => {
    if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      tab(event.key === 'Home' ? 'report' : event.key === 'End' ? 'tools' : ['report', 'tools'][1 - index], true);
    }
  };
}

$('nav-alerts').onclick = () => showView('alerts');
$('nav-cases').onclick = () => showView('cases');
$('back-to-cases').onclick = () => showView('cases');

function hasActiveCase() {
  return cases.some(record => ['running', 'disconnected'].includes(record.status));
}

function updateActions() {
  const active = hasActiveCase();
  $('new-investigation').disabled = !ready || active;
  $('new-investigation').title = active ? 'Finish or reconnect to the active investigation first.' : '';
  $('run').disabled = !ready || active;
  $('nav-case-count').textContent = cases.length;
  try {
    const history = cases.slice(-20).map(({ id, question, scope, started, job, status }) => ({
      id, question, scope, started, job, status
    }));
    sessionStorage.setItem('hunt-cases-v1', JSON.stringify(history));
  } catch (_) {
    /* Storage bị chặn không cản thao tác trên tab. */
  }
}

function badge(level, parent) {
  let className = 'badge';
  if (level >= 12)
    className += ' high';
  else if (level >= 7)
    className += ' elevated';
  return node('span', String(level), parent, className);
}

function timestamp(value, cell) {
  node('span', value.slice(11, 19), cell, 'time-primary');
  node('span', value.slice(0, 10) + ' UTC', cell, 'time-secondary');
}

function emptyRow(parent, columns, title, text) {
  const cell = node('td', undefined, node('tr', undefined, parent), 'table-empty');
  cell.colSpan = columns;
  node('span', title, cell, 'empty-title');
  node('span', text, cell);
}

async function loadAlerts(reset = false) {
  if (reset) {
    alertOffset = 0;
    explorerWindow = null;
  }
  if (!dataset || !dataset.source.ok) {
    $('alert-rows').replaceChildren();
    emptyRow(
      $('alert-rows'),
      6,
      dataset && !dataset.setup_required ? 'SOURCE UNAVAILABLE.' : 'SETUP REQUIRED.',
      'Check the connections above before browsing Wazuh alerts.'
    );
    $('alert-count').textContent = 'Alerts unavailable / no connected source';
    $('page-range').textContent = 'No source connected';
    $('previous-page').disabled = true;
    $('next-page').disabled = true;
    return;
  }
  const version = ++alertVersion;
  const limit = Number($('page-size').value);
  const params = new URLSearchParams({
    query: $('alert-search').value,
    agent_id: $('alert-agent').value,
    min_level: $('alert-level').value,
    limit,
    offset: alertOffset
  });
  if ($('alert-window').value === 'all') {
    params.set('all_time', 'true');
  } else if (explorerWindow) {
    params.set('start', explorerWindow.start);
    params.set('end', explorerWindow.end);
  } else if ($('alert-window').value) {
    params.set('hours', $('alert-window').value);
  }
  $('alert-count').textContent = 'Loading Wazuh alerts…';
  try {
    const result = await api('/api/alerts?' + params);
    // Bỏ response cũ khi bộ lọc đã đổi trong lúc request đang chạy.
    if (version !== alertVersion)
      return;
    alertTotal = result.total;
    explorerWindow = { start: result.start, end: result.end };
    $('snapshot').textContent = scopeTime(result);
    $('alert-rows').replaceChildren();
    if (!result.alerts.length)
      emptyRow($('alert-rows'), 6, 'NO MATCHING ALERTS.', 'Try a different agent, level, or log keyword.');
    for (const alert of result.alerts) {
      const row = node('tr', undefined, $('alert-rows'));
      const reference = node('td', undefined, row);
      const id = node('button', alertLabel(alert), reference, 'text-button');
      id.type = 'button';
      id.title = alert.id;
      id.onclick = () => openAlert(alert.id);
      const index = node('span', alert.index, reference, 'agent-name');
      index.title = alert.index;
      timestamp(alert.timestamp, node('td', undefined, row));
      const agent = node('td', undefined, row);
      node('span', alert.agent.id, agent);
      node('span', alert.agent.name, agent, 'agent-name');
      const description = node('span', alert.rule.description, node('td', undefined, row), 'description');
      description.title = alert.rule.description;
      badge(alert.rule.level, node('td', undefined, row));
      const action = node('td', undefined, row);
      action.className = 'action-column';
      const inspect = node('button', '{ }', action, 'icon-button');
      inspect.type = 'button';
      inspect.setAttribute('aria-label', 'Inspect ' + alert.id);
      inspect.onclick = () => openAlert(alert.id);
    }
    $('alert-count').textContent = result.total + ' matching Wazuh alerts';
    $('page-range').textContent = result.total
      ? (alertOffset + 1) + '–' + (alertOffset + result.alerts.length) + ' of ' + result.total + ' alerts'
      : '0 alerts';
    $('previous-page').disabled = alertOffset === 0;
    $('next-page').disabled = !result.has_more;
    $('page-error').textContent = result.pagination_limited
      ? 'Only the first 10,000 matches can be paged. Narrow the time window or search terms.'
      : '';
  } catch (error) {
    if (version === alertVersion) {
      $('page-error').textContent = error.message;
      $('alert-count').textContent = 'Could not load alerts. Use Refresh to try again.';
    }
  }
}

let searchTimer;
$('alert-search').oninput = () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => loadAlerts(true), 250);
};
for (const id of ['alert-agent', 'alert-level', 'alert-window', 'page-size'])
  $(id).onchange = () => loadAlerts(true);

$('refresh-alerts').onclick = () => initialize(false);
$('refresh-setup').onclick = () => initialize(false);

$('previous-page').onclick = () => {
  alertOffset = Math.max(0, alertOffset - Number($('page-size').value));
  loadAlerts();
};
$('next-page').onclick = () => {
  if (alertOffset + Number($('page-size').value) < alertTotal) {
    alertOffset += Number($('page-size').value);
    loadAlerts();
  }
};

// Dùng JSON đã giữ trong case; nếu chưa có thì đọc chi tiết qua API.
async function openAlert(id, known) {
  try {
    rawAlert = known || await api('/api/alerts/' + encodeURIComponent(id));
    $('raw-title').textContent = alertLabel(rawAlert);
    $('raw-meta').textContent = rawAlert.timestamp + ' / ' + rawAlert.agent.id +
      ' · ' + rawAlert.agent.name + ' / level ' + rawAlert.rule.level;
    $('raw-json').textContent = JSON.stringify(rawAlert, null, 2);
    $('investigate-alert').disabled = !ready || hasActiveCase();
    if (!$('alert-dialog').open)
      $('alert-dialog').showModal();
  } catch (error) {
    $('page-error').textContent = error.message;
  }
}

$('close-alert').onclick = () => $('alert-dialog').close();

// Nhãn dùng ID Wazuh, còn truy vấn/dẫn chứng dùng khóa index::document_id.
function alertLabel(alert) {
  return alert.alert_id || alert.document_id || alert.id;
}

function inputTime(iso) {
  return iso.slice(0, 19).replace('T', ' ');
}

function scopeTime(scope) {
  if (scope.start === null && scope.end === null)
    return 'ALL TIME / retained alerts';
  const bound = value => value ? inputTime(new Date(value).toISOString()) : 'Unbounded';
  return bound(scope.start) + ' > ' + bound(scope.end) + ' UTC';
}

// Giữ giá trị ngày cũ để chuyển lại Custom range.
function updateTimeRange() {
  const all = $('time-range').value === 'all';
  $('date-range').hidden = all;
  for (const id of ['start', 'end']) {
    $(id).disabled = all;
    $(id).required = !all;
  }
  $('time-range-note').textContent = all
    ? 'Search all alerts currently retained in the Wazuh Indexer. Agent and level filters still apply.'
    : 'Format: YYYY-MM-DD HH:mm:ss. Relative times refer to the current UTC time.';
}
$('time-range').onchange = updateTimeRange;

function openComposer(lead) {
  if (!dataset || $('new-investigation').disabled)
    return;
  $('question').value = lead
    ? 'Investigate ' + alertLabel(lead) + ' on agent ' + lead.agent.id +
      '. Search nearby events, read full details, build a timeline, and distinguish observations from hypotheses.'
    : examples.host;
  const end = new Date();
  const start = new Date(end.getTime() - dataset.window_hours * 3600000);
  $('start').value = inputTime(explorerWindow?.start || start.toISOString());
  $('end').value = inputTime(explorerWindow?.end || end.toISOString());
  $('time-range').value = $('alert-window').value === 'all' ? 'all' : 'custom';
  updateTimeRange();
  if (lead && ![...$('agent').children].some(option => option.value === lead.agent.id))
    node('option', lead.agent.id + ' / ' + lead.agent.name, $('agent')).value = lead.agent.id;
  $('agent').value = lead ? lead.agent.id : $('alert-agent').value;
  $('min').value = lead ? '0' : $('alert-level').value;
  $('max').value = '15';
  $('composer-error').textContent = '';
  $('composer').showModal();
  $('question').focus();
}

$('new-investigation').onclick = () => openComposer();
$('close-composer').onclick = () => $('composer').close();
$('investigate-alert').onclick = () => {
  $('alert-dialog').close();
  openComposer(rawAlert);
};

document.querySelectorAll('[data-example]').forEach(button => button.onclick = () => {
  $('question').value = examples[button.dataset.example];
});
$('question').onkeydown = event => {
  if ((event.ctrlKey || event.metaKey) && event.key === 'Enter' && !$('run').disabled) {
    event.preventDefault();
    $('investigation-form').requestSubmit();
  }
};

// Date tự chuẩn hóa ngày sai; đối chiếu lại chuỗi để từ chối ngày bị tràn.
function utc(value) {
  let text = value.trim().replace(' ', 'T').replace(/Z$/, '');
  if (/^\d{4}-\d\d-\d\dT\d\d:\d\d$/.test(text))
    text += ':00';
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d$/.test(text))
    throw Error('Use YYYY-MM-DD HH:mm:ss for UTC times.');
  const date = new Date(text + 'Z');
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 19) !== text)
    throw Error('Enter a valid UTC date and time.');
  return date.toISOString();
}

// Lọc lịch sử cục bộ của tab, không truy vấn Indexer.
function renderCases() {
  $('case-list').hidden = !!selectedCase;
  $('case-detail').hidden = !selectedCase;
  if (selectedCase) {
    renderCase(cases.find(record => record.id === selectedCase));
    return;
  }
  const query = $('case-search').value.trim().toLowerCase();
  const matches = cases.filter(record => (record.id + ' ' + record.question + ' ' + record.status).toLowerCase().includes(query));
  $('case-count').textContent = matches.length + ' investigation' + (matches.length === 1 ? '' : 's');
  $('case-rows').replaceChildren();
  if (!matches.length)
    emptyRow(
      $('case-rows'),
      7,
      cases.length ? 'NO MATCHING CASES.' : 'NO INVESTIGATIONS YET.',
      cases.length ? 'Try a different search.' : 'Start a new investigation or inspect an alert as a lead.'
    );
  for (const record of [...matches].reverse()) {
    const row = node('tr', undefined, $('case-rows'));
    const id = node('button', record.id, node('td', undefined, row), 'text-button');
    id.type = 'button';
    id.onclick = () => showView('cases', record.id);
    const prompt = node('span', record.question, node('td', undefined, row), 'history-question');
    prompt.title = record.question;
    node('span', record.status.toUpperCase(), node('td', undefined, row), 'badge ' + record.status);
    node('td', record.tools.length, row);
    node('td', record.result ? Object.keys(record.result.report.evidence).length : '—', row);
    timestamp(record.started, node('td', undefined, row));
    const action = node('td', undefined, row);
    action.className = 'action-column';
    const open = node('button', '>', action, 'icon-button');
    open.type = 'button';
    open.setAttribute('aria-label', 'Open ' + record.id);
    open.onclick = () => showView('cases', record.id);
  }
}

$('case-search').oninput = renderCases;

function citation(id, parent, evidence) {
  const button = node('button', (evidence[id] ? alertLabel(evidence[id]) : id) + ' ↗', parent, 'cite');
  button.title = id;
  button.type = 'button';
  button.onclick = () => openAlert(id, evidence[id]);
}

function heading(title, parent) {
  return node('h3', title, parent, 'section-heading');
}

function coverageText(coverage) {
  const hasAnalysisCount = Number.isInteger(coverage.alerts_analyzed);
  const parts = [
    coverage.search_calls + ' search calls',
    coverage.detail_calls + ' detail calls',
    coverage.candidate_ids_returned + ' candidate IDs',
    coverage.alerts_inspected + (hasAnalysisCount ? ' source alerts read' : ' alerts inspected')
  ];
  if (hasAnalysisCount)
    parts.push(coverage.alerts_analyzed + ' of ' + coverage.alerts_inspected + ' alerts assessed by model');
  if (Number.isInteger(coverage.analysis_batches))
    parts.push(coverage.analysis_batches + ' analysis batches');
  if (coverage.analysis_failures)
    parts.push(coverage.analysis_failures + ' analysis failures');
  if (coverage.model_parse_errors)
    parts.push(coverage.model_parse_errors + ' model JSON errors');
  if (coverage.model_timeouts)
    parts.push(coverage.model_timeouts + ' Ollama timeouts');
  if (coverage.automatic_calls)
    parts.push(coverage.automatic_calls + ' automatic tool calls');
  if (coverage.cached_calls)
    parts.push(coverage.cached_calls + ' cached tool calls');
  if (coverage.planning_limit_reached)
    parts.push('query-planning limit reached');
  return 'COVERAGE / ' + parts.join(' / ');
}

function renderReportSummary(data, root) {
  const evidenceCount = Object.keys(data.report.evidence).length;
  node('p', data.report.summary, root, 'report-summary');
  const meta = node('div', undefined, root, 'report-meta');
  [
    data.model,
    data.tool_calls + ' tool calls',
    evidenceCount + (Number.isInteger(data.coverage?.alerts_analyzed) ? ' source alerts read' : ' source alerts inspected'),
    evidenceCount ? 'Alert IDs checked' : 'No inspected evidence'
  ].forEach(text => node('span', text, meta));
  if (evidenceCount)
    node('p', 'Citations link to inspected source records. Review the evidence and limitations before acting on any assessment.', root, 'field-note');
  if (data.coverage) {
    const line = node('p', coverageText(data.coverage), root, 'case-scope');
    line.title = data.coverage.planning_stop_reason || '';
  }
  for (const query of data.coverage?.queries || []) {
    const label = query.arguments.technique_id || query.arguments.query || 'All alerts';
    const text = 'QUERY / ' + label + ' / ' + query.inspected + ' of ' + query.total + ' matches read / COLLECTION ' +
      (query.exhausted ? 'EXHAUSTED' : 'PARTIAL');
    const line = node('p', text, root, 'case-scope');
    line.title = query.stop_reason || 'All matching records were read. Model assessment coverage is listed separately when available.';
  }
}

function renderFindings(report, coverage, root) {
  heading('Findings', root);
  const findings = node('div', undefined, root, 'findings');
  if (!report.findings.length) {
    let message = 'No findings in the retrieved evidence.';
    if (coverage?.model_timeouts || coverage?.report_rejected || coverage?.analysis_failures) {
      message = 'No completed model assessment. Review evidence coverage and investigation limits.';
      if (coverage.alerts_analyzed > 0)
        message = 'No findings in completed assessments. Review assessed counts and remaining source evidence.';
    }
    node('p', message, findings, 'muted');
  }
  report.findings.forEach((finding, index) => {
    const box = node('article', undefined, findings, 'finding');
    const title = node('h3', undefined, box);
    node('span', 'F' + String(index + 1).padStart(2, '0'), title, 'finding-index');
    node('span', finding.title, title);
    node('p', finding.analysis, box);
    finding.evidence_ids.forEach(id => citation(id, box, report.evidence));
  });
}

function eventTimeLabel(source) {
  switch (source) {
    case 'timestamp':
      return 'Alert time';
    case 'data.win.eventdata.utcTime':
      return 'Sysmon event time';
    default:
      return 'Windows event time';
  }
}

function renderTimeline(report, root) {
  heading('Evidence timeline / UTC', root);
  const timeline = node('div', undefined, root);
  if (!report.timeline.length)
    node('p', 'No relevant inspected events are available for a timeline.', timeline, 'muted');
  for (const event of report.timeline) {
    const box = node('article', undefined, timeline, 'event');
    const top = node('div', undefined, box, 'event-head');
    const time = node('time', event.timestamp.replace('T', ' / ').replace('Z', ' UTC'), top);
    time.dateTime = event.timestamp;
    const timeSource = event.timestamp_source || 'timestamp';
    node('span', eventTimeLabel(timeSource), top, 'event-agent');
    if (event.alert_timestamp && event.alert_timestamp !== event.timestamp)
      node('div', 'Alert time / ' + event.alert_timestamp.replace('T', ' / ').replace('Z', ' UTC'), box, 'event-agent');
    node('span', event.agent.id + ' / ' + event.agent.name, top, 'event-agent');
    badge(event.rule.level, top);
    node('p', event.analysis, box);
    citation(event.alert_id, box, report.evidence);
  }
}

function renderReportNotes(report, root) {
  const notes = node('div', undefined, root, 'notes');
  for (const [key, title, extraKey, extraTitle] of [
    ['recommendations', 'Follow-up checks', 'additional_recommendations', 'Additional batch suggestions'],
    ['limitations', 'Limits & uncertainty', 'batch_limitations', 'Additional model notes']
  ]) {
    const section = node('section', undefined, notes);
    heading(title, section);
    const list = node('ul', undefined, section);
    report[key].forEach(text => node('li', text, list));
    const extra = report[extraKey] || [];
    if (!extra.length)
      continue;
    const detail = node('details', undefined, section);
    node('summary', extraTitle + ' (' + extra.length + ')', detail);
    let loaded = false;
    // Chỉ tạo danh sách phụ khi mở để báo cáo lớn không sinh hết DOM ngay.
    detail.ontoggle = () => {
      if (!detail.open || loaded)
        return;
      const extraList = node('ul', undefined, detail);
      extra.forEach(text => node('li', text, extraList));
      loaded = true;
    };
  }
}

// Chỉ format JSON lần đầu mở mục; giữ nguyên dữ liệu bằng chứng.
function lazyJson(detail, value) {
  const pre = node('pre', undefined, detail);
  let loaded = false;
  detail.ontoggle = () => {
    if (!detail.open || loaded)
      return;
    pre.textContent = JSON.stringify(value, null, 2);
    loaded = true;
  };
}

function renderSourceEvidence(evidence, root) {
  heading('Source evidence / Wazuh JSON', root);
  for (const [id, alert] of Object.entries(evidence)) {
    const detail = node('details', undefined, root);
    const summary = node('summary', undefined, detail);
    node('strong', id, summary);
    node('span', alert.rule.description, summary);
    lazyJson(detail, alert);
  }
}

function renderReport(data) {
  const root = $('report');
  root.replaceChildren();
  renderReportSummary(data, root);
  renderFindings(data.report, data.coverage, root);
  renderTimeline(data.report, root);
  renderReportNotes(data.report, root);
  renderSourceEvidence(data.report.evidence, root);
}

function renderReportPlaceholder(status) {
  let title = 'FOLLOWING THE SIGNAL.';
  let message = 'The agent is collecting evidence. Tool activity shows the actual queries.';
  switch (status) {
    case 'disconnected':
      title = 'INVESTIGATION INCOMPLETE.';
      message = 'Progress is retained by the app. Reconnect to continue watching this investigation.';
      break;
    case 'failed':
      title = 'INVESTIGATION INCOMPLETE.';
      message = 'Review the error above. No completed report is available.';
      break;
  }
  $('report-empty').querySelector('.pixel').textContent = title;
  $('report-empty').querySelector('p').textContent = message;
}

function toolResultLabel(result) {
  if (result.error)
    return 'TOOL ERROR';
  if (result.cached)
    return 'ALREADY COLLECTED / ' + (result.collection?.inspected ?? 0) + ' of ' +
      (result.collection?.total ?? result.total ?? 0) + ' read';
  if (result.total !== undefined)
    return result.total + ' matches / ' + result.alerts.length + ' returned';
  return result.alerts.length + ' full alerts';
}

function renderTool(entry, parent) {
  const detail = node('details', undefined, parent);
  const summary = node('summary', undefined, detail);
  node('strong', String(entry.step).padStart(2, '0') + ' / ' + entry.tool +
    (entry.origin === 'backend' ? ' / AUTO' : ''), summary);
  node('span', toolResultLabel(entry.result), summary, entry.result.error ? 'trace-error' : 'trace-info');
  lazyJson(detail, { origin: entry.origin || 'model', arguments: entry.arguments, result: entry.result });
}

// Tool events chỉ được nối thêm; giữ các dòng cũ để bảo toàn trạng thái đang mở.
function renderCaseTools(record) {
  $('tool-count').textContent = record.tools.length;
  $('tools-empty').hidden = !!record.tools.length;
  $('tools-empty').textContent = record.status === 'running'
    ? 'Waiting for Ollama to choose its first tool…'
    : 'No tool calls have been received for this investigation.';
  if (record.tools.length < caseView.toolCount) {
    $('trace').replaceChildren();
    caseView.toolCount = 0;
  }
  for (let index = caseView.toolCount; index < record.tools.length; index++)
    renderTool(record.tools[index], $('trace'));
  caseView.toolCount = record.tools.length;
}

// Chỉ dựng lại báo cáo khi đổi case hoặc nhận kết quả mới.
function renderCase(record) {
  if (!record)
    return;
  if (caseView.record !== record) {
    caseView.record = record;
    caseView.result = null;
    caseView.toolCount = 0;
    $('report').replaceChildren();
    $('trace').replaceChildren();
  }
  $('case-id').textContent = record.id;
  $('case-state').textContent = record.status.toUpperCase();
  $('case-state').className = 'badge ' + record.status;
  $('case-question').textContent = record.question;
  $('case-scope').textContent = 'SCOPE / ' + (record.scope.agent_id || 'All agents') +
    ' / levels ' + record.scope.min_level + '–' + record.scope.max_level +
    ' / ' + scopeTime(record.scope);
  $('case-progress').textContent = record.message;
  $('case-error').textContent = record.error || '';
  $('reconnect').hidden = record.status !== 'disconnected';
  $('reconnect').disabled = record.watching;
  $('report-empty').hidden = !!record.result;
  if (caseView.result !== record.result) {
    if (record.result)
      renderReport(record.result);
    else
      $('report').replaceChildren();
    caseView.result = record.result;
  }
  if (!record.result)
    renderReportPlaceholder(record.status);
  renderCaseTools(record);
}

function updateCase() {
  updateActions();
  if (view === 'cases')
    renderCases();
}

function resultMessage(status, coverage) {
  switch (status) {
    case 'inconclusive':
      return 'Investigation inconclusive / review evidence coverage and gaps.';
    case 'partial':
      if (coverage?.model_timeouts)
        return 'Ollama timed out / retained source evidence is available for review.';
      if (coverage?.report_rejected)
        return 'Model report rejected / retained source evidence is available for review.';
      if (coverage?.analysis_failures)
        return 'Batched analysis incomplete / review completed assessments and retained source evidence.';
      return 'Partial report / review evidence coverage and collection limits.';
    default:
      if (status === 'complete' && coverage?.planning_limit_reached)
        return 'Completed for executed queries / query-planning limit reached.';
      return 'Investigation finished / review findings and evidence gaps.';
  }
}

function consume(record, event) {
  switch (event.type) {
    case 'status':
      record.message = event.data.message;
      break;
    case 'tool':
      record.tools.push(event.data);
      break;
    case 'result':
      record.result = event.data;
      record.status = event.data.outcome || 'complete';
      record.error = '';
      record.message = resultMessage(record.status, event.data.coverage);
      if (selectedCase === record.id)
        tab('report');
      break;
    case 'error':
      record.status = 'failed';
      record.error = event.data.message;
      record.message = 'The investigation stopped. Review the error below.';
      break;
  }
}

const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

// Theo dõi cùng job/cursor; thử lại lỗi mạng tối đa ba lần trước khi cho nối lại thủ công.
async function watch(record) {
  if (record.watching)
    return;
  record.watching = true;
  record.status = 'running';
  record.error = '';
  updateCase();
  let failures = 0;
  try {
    while (record.status === 'running') {
      try {
        const snapshot = await api('/api/investigations/' + record.job + '?after=' + record.cursor);
        failures = 0;
        record.error = '';
        for (const event of snapshot.events)
          consume(record, event);
        // Tăng cursor sau khi ghép sự kiện để không hiển thị lặp nhật ký tool.
        record.cursor = snapshot.next_offset;
        if (snapshot.status !== 'running' && record.status === 'running') {
          record.status = 'failed';
          record.error = 'The investigation ended without a report. Start a new request.';
        }
        if (snapshot.events.length || record.status !== 'running')
          updateCase();
      } catch (error) {
        // Không retry lỗi 4xx như job đã hết hạn.
        if (error.status !== 0 && !(error.status >= 500)) {
          record.status = 'failed';
          record.error = error.message;
          record.message = 'Could not retrieve the investigation.';
          updateCase();
          break;
        }
        failures++;
        record.message = 'Connection interrupted / reconnecting ' + failures + ' of 3…';
        if (failures >= 3) {
          record.status = 'disconnected';
          record.error = error.message;
          record.message = 'Connection lost. The app retains this investigation; reconnect without starting another one.';
        }
        updateCase();
      }
      if (record.status === 'running')
        await pause(1000);
    }
  } finally {
    record.watching = false;
    updateCase();
  }
}

$('reconnect').onclick = () => {
  const record = cases.find(item => item.id === selectedCase);
  if (record)
    watch(record);
};

// Tạo một job rồi polling mã trả về; reconnect không gửi lại POST.
$('investigation-form').onsubmit = async event => {
  event.preventDefault();
  $('composer-error').textContent = '';
  let scope;
  try {
    const all = $('time-range').value === 'all';
    scope = {
      start: all ? null : utc($('start').value),
      end: all ? null : utc($('end').value),
      agent_id: $('agent').value,
      min_level: Number($('min').value),
      max_level: Number($('max').value)
    };
    if (!$('question').value.trim())
      throw Error('Enter an investigation prompt.');
    if (scope.start > scope.end)
      throw Error('Start time must be before or equal to end time.');
    if (!Number.isInteger(scope.min_level) || !Number.isInteger(scope.max_level) ||
        scope.min_level < 0 || scope.max_level > 15 || scope.min_level > scope.max_level)
      throw Error('Levels must be integers from 0 to 15; minimum cannot exceed maximum.');
  } catch (error) {
    $('composer-error').textContent = error.message;
    return;
  }
  const sequence = Math.max(0, ...cases.map(record => Number(record.id.slice(5)) || 0)) + 1;
  const record = {
    id: 'HUNT-' + String(sequence).padStart(3, '0'),
    question: $('question').value.trim(),
    scope,
    started: new Date().toISOString(),
    status: 'running',
    message: 'Starting the investigation…',
    error: '',
    tools: [],
    result: null,
    job: null,
    cursor: 0,
    watching: false
  };
  cases.push(record);
  $('composer').close();
  showView('cases', record.id);
  tab('tools');
  updateActions();
  try {
    const response = await api('/api/investigate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: record.question, scope })
    });
    record.job = response.job_id;
    await watch(record);
  } catch (error) {
    record.status = 'failed';
    record.error = error.message;
    record.message = 'The request could not be started.';
    updateCase();
  }
};

function renderConnections(status) {
  $('nav-alert-count').textContent = status.total === null ? '—' : status.total;
  $('snapshot').textContent = 'QUERY WINDOW / UTC';
  $('model').textContent = status.model;
  $('engine-state').className = 'engine-state' + (status.ollama.ok ? ' online' : '');
  $('engine-label').textContent = status.ollama.ok ? 'OLLAMA ONLINE' : 'OLLAMA UNAVAILABLE';
  $('engine-error').textContent = status.ollama.ok ? '' : status.ollama.message;
  $('setup-panel').hidden = status.ready;
  $('setup-title').textContent = status.setup_required ? 'SETUP REQUIRED' : 'CONNECTION STATUS';
  $('connection-status').replaceChildren();
  const services = [
    ['Indexer / required', status.source],
    ['Ollama / required', status.ollama],
    ['Wazuh API / optional agent metadata', status.manager]
  ];
  for (const [name, state] of services) {
    const item = node('li', undefined, $('connection-status'));
    node('strong', name + ': ' + (state.ok ? 'Connected' : 'Not ready'), item);
    node('p', state.message, item);
  }
  for (const id of ['alert-search', 'alert-agent', 'alert-level', 'alert-window', 'page-size'])
    $(id).disabled = !status.source.ok;
}

function renderAgents(agents, limited) {
  const previousAgent = $('alert-agent').value;
  for (const id of ['alert-agent', 'agent']) {
    $(id).replaceChildren();
    node('option', 'All agents', $(id)).value = '';
  }
  $('agent-links').replaceChildren();
  for (const agent of agents) {
    for (const id of ['alert-agent', 'agent'])
      node('option', agent.id + ' / ' + agent.name, $(id)).value = agent.id;
    const button = node('button', undefined, $('agent-links'), 'agent-link');
    button.type = 'button';
    node('span', agent.id, button, 'agent-id');
    node('span', agent.name, button);
    button.onclick = () => {
      $('alert-agent').value = agent.id;
      showView('alerts');
      loadAlerts(true);
    };
  }
  $('alert-agent').value = agents.some(agent => agent.id === previousAgent) ? previousAgent : '';
  if (limited)
    node('p', 'Agent list capped at 500 entries.', $('agent-links'), 'sidebar-note');
}

// sessionStorage chỉ giữ metadata; báo cáo và bằng chứng phải lấy lại từ server.
function restoreCases() {
  try {
    const saved = JSON.parse(sessionStorage.getItem('hunt-cases-v1') || '[]');
    if (!Array.isArray(saved))
      return;
    for (const record of saved.slice(-20)) {
      if (!record || !/^HUNT-\d+$/.test(record.id) || typeof record.question !== 'string' || !record.scope)
        continue;
      const resumable = /^[a-f0-9]{32}$/.test(record.job || '');
      cases.push({
        ...record,
        status: resumable ? 'running' : 'failed',
        message: resumable ? 'Restoring saved investigation progress…' : 'This request has no saved server task.',
        error: '',
        tools: [],
        result: null,
        cursor: 0,
        watching: false
      });
    }
  } catch (_) {
    /* Lịch sử tab là tùy chọn. */
  }
}

async function initialize(restore = true) {
  try {
    $('refresh-setup').disabled = true;
    dataset = await api('/api/status');
    ready = dataset.ready;
    renderConnections(dataset);
    renderAgents(dataset.agents, dataset.agent_list_limited);
    if (restore && !cases.length)
      restoreCases();
    updateActions();
    await loadAlerts(true);
    if (restore)
      for (const record of cases)
        if (record.status === 'running' && record.job)
          watch(record);
  } catch (error) {
    ready = false;
    updateActions();
    $('page-error').textContent = error.message;
    $('engine-label').textContent = 'APP UNAVAILABLE';
  } finally {
    $('refresh-setup').disabled = false;
  }
}

initialize();
