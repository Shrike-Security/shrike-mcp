import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { KeyRotationManager } from './keyRotation.js';
import type { KeyProvider } from './keyProvider.js';

function createMockProvider(keys: (string | null)[]): KeyProvider {
  let callIndex = 0;
  return {
    getKey: vi.fn(async () => {
      const key = keys[Math.min(callIndex, keys.length - 1)];
      callIndex++;
      return key;
    }),
    name: () => 'mock',
  };
}

describe('KeyRotationManager', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('initializes with the first key from provider', async () => {
    const provider = createMockProvider(['key_v1']);
    const manager = new KeyRotationManager(provider, { pollIntervalMs: 0 });
    const key = await manager.initialize();
    expect(key).toBe('key_v1');
    expect(manager.getKey()).toBe('key_v1');
    manager.stop();
  });

  it('initializes with null when provider returns null', async () => {
    const provider = createMockProvider([null]);
    const manager = new KeyRotationManager(provider, { pollIntervalMs: 0 });
    const key = await manager.initialize();
    expect(key).toBeNull();
    manager.stop();
  });

  it('detects key rotation on poll', async () => {
    const onKeyChanged = vi.fn();
    const provider = createMockProvider(['key_v1', 'key_v2']);
    const manager = new KeyRotationManager(provider, {
      pollIntervalMs: 1000,
      onKeyChanged,
    });

    await manager.initialize();
    expect(manager.getKey()).toBe('key_v1');
    expect(onKeyChanged).not.toHaveBeenCalled();

    // Advance past poll interval
    await vi.advanceTimersByTimeAsync(1000);

    expect(manager.getKey()).toBe('key_v2');
    expect(onKeyChanged).toHaveBeenCalledWith('key_v2');
    expect(onKeyChanged).toHaveBeenCalledTimes(1);
    manager.stop();
  });

  it('does not fire callback when key is unchanged', async () => {
    const onKeyChanged = vi.fn();
    const provider = createMockProvider(['key_v1', 'key_v1', 'key_v1']);
    const manager = new KeyRotationManager(provider, {
      pollIntervalMs: 1000,
      onKeyChanged,
    });

    await manager.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await vi.advanceTimersByTimeAsync(1000);

    expect(onKeyChanged).not.toHaveBeenCalled();
    expect(manager.getKey()).toBe('key_v1');
    manager.stop();
  });

  it('retains old key when poll fails', async () => {
    const onKeyChanged = vi.fn();
    const provider: KeyProvider = {
      getKey: vi.fn()
        .mockResolvedValueOnce('key_v1')
        .mockRejectedValueOnce(new Error('network error'))
        .mockResolvedValueOnce('key_v1'),
      name: () => 'mock',
    };
    const manager = new KeyRotationManager(provider, {
      pollIntervalMs: 1000,
      onKeyChanged,
    });

    await manager.initialize();
    expect(manager.getKey()).toBe('key_v1');

    // Poll fails
    await vi.advanceTimersByTimeAsync(1000);
    expect(manager.getKey()).toBe('key_v1');
    expect(onKeyChanged).not.toHaveBeenCalled();
    manager.stop();
  });

  it('retains old key when poll returns null', async () => {
    const provider = createMockProvider(['key_v1', null]);
    const manager = new KeyRotationManager(provider, { pollIntervalMs: 1000 });

    await manager.initialize();
    await vi.advanceTimersByTimeAsync(1000);

    // null doesn't overwrite existing key
    expect(manager.getKey()).toBe('key_v1');
    manager.stop();
  });

  it('does not poll when pollIntervalMs is 0', async () => {
    const provider = createMockProvider(['key_v1', 'key_v2']);
    const manager = new KeyRotationManager(provider, { pollIntervalMs: 0 });

    await manager.initialize();
    await vi.advanceTimersByTimeAsync(600000); // 10 minutes

    // Only called once (initialize), never polled
    expect(provider.getKey).toHaveBeenCalledTimes(1);
    expect(manager.getKey()).toBe('key_v1');
    manager.stop();
  });

  it('stop() clears the polling interval', async () => {
    const provider = createMockProvider(['key_v1', 'key_v2']);
    const manager = new KeyRotationManager(provider, { pollIntervalMs: 1000 });

    await manager.initialize();
    manager.stop();

    await vi.advanceTimersByTimeAsync(5000);

    // Only the initial call, no polls after stop
    expect(provider.getKey).toHaveBeenCalledTimes(1);
  });

  it('refresh() forces an immediate key fetch', async () => {
    vi.useRealTimers(); // refresh() is async, doesn't need fake timers

    const provider: KeyProvider = {
      getKey: vi.fn()
        .mockResolvedValueOnce('key_v1')
        .mockResolvedValueOnce('key_v2'),
      name: () => 'mock',
    };
    const onKeyChanged = vi.fn();
    const manager = new KeyRotationManager(provider, {
      pollIntervalMs: 0,
      onKeyChanged,
    });

    await manager.initialize();
    expect(manager.getKey()).toBe('key_v1');

    await manager.refresh();
    expect(manager.getKey()).toBe('key_v2');
    expect(onKeyChanged).toHaveBeenCalledWith('key_v2');
    manager.stop();
  });

  it('refresh() retains old key on error', async () => {
    vi.useRealTimers();

    const provider: KeyProvider = {
      getKey: vi.fn()
        .mockResolvedValueOnce('key_v1')
        .mockRejectedValueOnce(new Error('boom')),
      name: () => 'mock',
    };
    const manager = new KeyRotationManager(provider, { pollIntervalMs: 0 });

    await manager.initialize();
    await manager.refresh();
    expect(manager.getKey()).toBe('key_v1');
    manager.stop();
  });

  it('calls provider.close() on stop if available', async () => {
    const closeFn = vi.fn();
    const provider: KeyProvider = {
      getKey: vi.fn().mockResolvedValue('key'),
      name: () => 'mock',
      close: closeFn,
    };
    const manager = new KeyRotationManager(provider, { pollIntervalMs: 0 });
    await manager.initialize();
    manager.stop();
    expect(closeFn).toHaveBeenCalledTimes(1);
  });
});
