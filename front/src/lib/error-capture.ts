let lastError: Error | null = null;

// Save the original console.error to avoid infinite recursion and to preserve original logging
const originalConsoleError = console.error;

// Capture errors logged to console.error
console.error = function (...args: any[]) {
  for (const arg of args) {
    if (arg instanceof Error) {
      lastError = arg;
      break;
    }
  }
  originalConsoleError.apply(console, args);
};

// Also listen to unhandled exceptions/rejections if running in Node.js/Bun server environment
if (typeof process !== "undefined") {
  process.on("uncaughtException", (err) => {
    lastError = err;
  });
  process.on("unhandledRejection", (reason) => {
    if (reason instanceof Error) {
      lastError = reason;
    } else {
      lastError = new Error(String(reason));
    }
  });
}

/**
 * Returns the last captured error and resets the internal state.
 */
export function consumeLastCapturedError(): Error | null {
  const err = lastError;
  lastError = null;
  return err;
}
