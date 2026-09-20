/* Test fixture mimicking frida-agent: exported entry symbol, fingerprint
 * strings, and a binary (non-string) region. Built as a shared library and
 * embedded into the fixture host exactly like frida-server embeds the agent
 * via GResource (raw bytes inside .rodata). */

const char *agent_banner = "frida-agent (embedded)";
const char *rpc_marker = "frida:rpc";
const char *gum_api = "GumQuickApi FRIDA_GUMJS test";

/* raw binary data that must survive untouched */
const char fake_png[] = {
    0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A,
    0x00, 0x00, 0x00, 0x0D, 'I', 'H', 'D', 'R',
    0x08, 0x08, 0x08, 0xDB, 0x00, 0x00, 0x00, 0x00,
    0x42, 0x00, 0x00, 0x42, 0xFF, 0x21, 0x00, 0x9E,
};

int frida_agent_main(void)
{
    return 42;
}
