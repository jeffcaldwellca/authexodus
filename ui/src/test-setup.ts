import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";

// The wizard keeps the device and the safety ticks in sessionStorage across a window reload;
// each test starts with a fresh window.
afterEach(() => { sessionStorage.clear(); });
