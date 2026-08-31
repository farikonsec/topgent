// The three things a panel needs from the application, without importing it.
//
// A panel that called `render()` directly would have to import the module that
// imports the panel, and a cycle through the entry point is the kind of thing
// that works until someone reorders two imports. Instead the application fills
// these in at startup and panels reach them through here.

/** Set by the application at startup; panels call through these. */
export const app = {
  /** Redraw every panel from the current report. */
  render: () => {},
  /** Fetch a fresh report. */
  poll: async () => {},
  /** Open the confirmation for stopping an agent. */
  askStop: () => {},
};
