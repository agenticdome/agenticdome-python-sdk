# Framework-specific offline trials

Each script runs the same fixed normal and hostile inputs through the core SDK
in `local_sim` mode. No account, key, network connection, or third-party
framework install is required.

```bash
python examples/frameworks/crewai.py
python examples/frameworks/langgraph.py
python examples/frameworks/mcp.py
```

The common runner forces offline mode and removes live credentials for the
demonstration process. A script's framework name labels the payload and prints
the relevant production import; it does not import, instantiate, or test that
third-party framework. The printed import is a next-step pointer, not proof
that the application is attached. See the [examples guide](../README.md) for
the complete framework/install matrix and the boundary between simulation,
live engine decisions, and real framework attachment.

For production, do not stop at the printed import. Follow the [production integration playbook](../PRODUCTION_INTEGRATION.md), then use the linked framework-native example in the main SDK README. The playbook identifies the exact construction file, first public attachment call, sensitive tool boundary and bypasses that must be removed for each framework.
