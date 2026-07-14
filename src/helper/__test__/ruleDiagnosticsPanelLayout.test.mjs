import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const componentPath = path.resolve('src/components/rules/RuleDiagnosticsPanel.vue')

test('rule diagnostics panel keeps diagnostics cards fixed height with inner scrolling', () => {
  const source = fs.readFileSync(componentPath, 'utf8')

  assert.match(source, /h-\[20rem\]/)
  assert.match(source, /overflow-hidden/)
  assert.match(source, /overflow-y-auto/)
})
