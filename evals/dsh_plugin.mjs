// 仅使用 dsh 公开扩展接口；先验证拒绝保护，再释放 headless 入口。
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const name = 'planner-deny-all';
export const inject = ['tools', 'systemPrompt', 'agentDefaultModel', 'sessions'];
const root = dirname(fileURLToPath(import.meta.url));
const denial = 'PLANNER_DENY_ALL_NATIVE_TOOLS';

export async function apply(ctx) {
  const input = JSON.parse(readFileSync(join(root, 'input.json'), 'utf8'));
  const state = {
    status: 'initializing', model: null, provider: null, content: '', usage: {},
    guard_self_test_denied: false, sentinel_body_executed: false,
    tool_attempts: 0, model_tool_calls: 0, filtered_tool_schema_count: 0,
    original_tool_schema_count: null,
  };
  const save = () => writeFileSync(join(root, 'planner-result.json'), JSON.stringify(state, null, 2));
  ctx.tools.guard((execution) => {
    if (execution.name !== 'planner_guard_sentinel') state.tool_attempts += 1;
    return denial;
  });
  const unregister = ctx.tools.register({
    name: 'planner_guard_sentinel', description: '拒绝保护自测哨兵', parameters: {},
    output: { schema: { type: 'boolean' }, render: (_args, value) => [{ type: 'text', text: String(value) }] },
    execute: async () => { state.sentinel_body_executed = true; return true; },
  });
  const result = await ctx.tools.execute({
    callId: 'planner-guard-self-test', name: 'planner_guard_sentinel', arguments: {},
    signal: new AbortController().signal,
  });
  unregister();
  state.guard_self_test_denied = result.isError === true && result.error?.message === denial
    && !state.sentinel_body_executed;
  if (!state.guard_self_test_denied) {
    state.status = 'guard_failed'; save(); throw new Error('GUARD_FAILED');
  }
  ctx.on('system-prompt/assemble', (assembly) => {
    const selection = ctx.agentDefaultModel.currentSelection();
    const actualModel = assembly.variables?.model;
    if (selection.provider !== input.expected_provider || selection.model !== input.expected_model
        || actualModel !== input.expected_model) {
      state.status = 'model_mismatch'; save(); throw new Error('MODEL_MISMATCH');
    }
    state.original_tool_schema_count = assembly.tools.length;
    state.model = actualModel;
    state.provider = selection.provider;
    return { ...assembly, tools: [] };
  });
  ctx.on('session/event', (_session, event) => {
    if (event.type === 'assistant/message') {
      const data = event.data;
      const message = data.message;
      state.model_tool_calls += message.content.filter((block) => block.type === 'tool-call').length;
      const source = message.source ?? {};
      state.model = source.model ?? null;
      state.provider = source.provider ?? null;
      state.content = message.content.filter((block) => block.type === 'text')
        .map((block) => block.text).join('');
      // 仅保存数值用量，不保存 provider 回放字段或任何认证材料。
      for (const [key, value] of Object.entries(data.usage ?? {})) {
        if (typeof value === 'number' && Number.isFinite(value)) {
          state.usage[key] = (state.usage[key] ?? 0) + value;
        }
      }
    }
    if (event.type === 'turn/end') {
      state.status = event.data.reason?.kind ?? 'unknown';
      state.termination_reason = event.data.reason?.reason?.kind ?? null;
      state.error_code = event.data.reason?.error?.code ?? null;
      if (state.model !== input.expected_model || state.provider !== input.expected_provider) {
        state.status = 'model_mismatch';
      }
      save();
    }
  });
  const task = [
    '你是动作规划器。以下 messages 是按时间顺序排列的完整对话；请依据其中的任务生成下一步动作。',
    '你只能输出符合下列 schema 的一个 JSON 对象，不加 Markdown 围栏或说明。',
    '禁止调用任何原生工具、命令、文件、网络、子智能体或工作流。业务工具名称只可作为 JSON 字段值，由外部受控执行器决定执行。',
    JSON.stringify({ messages: input.messages, schema: input.schema }),
  ].join('\n');
  state.status = 'ready';
  ctx.provide('plannerNoTools', { task });
}
