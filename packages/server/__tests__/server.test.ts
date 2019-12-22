import test from 'ava'

import index from '../src/index'

test('foo', t => {
  t.is(index.test('Testing'), 'Testing')
})
