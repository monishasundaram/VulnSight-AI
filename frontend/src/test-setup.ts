import '@testing-library/jest-dom/vitest';

if (typeof globalThis.ResizeObserver === 'undefined') {
  class TestResizeObserver {
    constructor(_callback: ResizeObserverCallback) {}
    observe(_target: Element) {}
    unobserve(_target: Element) {}
    disconnect() {}
  }
  Object.defineProperty(globalThis, 'ResizeObserver', { configurable: true, writable: true, value: TestResizeObserver });
}
