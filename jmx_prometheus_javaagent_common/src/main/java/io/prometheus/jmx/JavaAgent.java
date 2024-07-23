package io.prometheus.jmx;

import io.prometheus.client.CollectorRegistry;
import io.prometheus.client.exporter.HTTPServer;
import io.prometheus.client.hotspot.DefaultExports;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.ProtectionDomain;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;

public class JavaAgent {

  static HTTPServer server;

  public static void agentmain(String agentArgument, Instrumentation instrumentation) throws Exception {
    premain(agentArgument, instrumentation);
  }

  public static void premain(String agentArgument, Instrumentation instrumentation) throws Exception {
    // Bind to all interfaces by default (this includes IPv6).
    String host = "0.0.0.0";

    try {
      Config config = parseConfig(agentArgument, host);

      new BuildInfoCollector().register();
      new JmxCollector(new File(config.file), JmxCollector.Mode.AGENT).register();
      DefaultExports.initialize();
      server = new HTTPServer(config.socket, CollectorRegistry.defaultRegistry, true);
    } catch (IllegalArgumentException e) {
      System.err.println("Usage: -javaagent:/path/to/JavaAgent.jar=[host:]<port>:<yaml configuration file> " + e.getMessage());
      System.exit(1);
    }


    String replaceHostNameWithIp = System.getenv().get("REPLACE_HOSTNAME_WITH_IP");
    if (replaceHostNameWithIp != null && replaceHostNameWithIp.equalsIgnoreCase("true")) {
      // intercept InetSocketAddress:getHostName
      AgentBuilder.Transformer hostNameTransformer = new AgentBuilder.Transformer() {
        @Override
        public DynamicType.Builder<?> transform(DynamicType.Builder<?> builder,
                                                TypeDescription typeDescription,
                                                ClassLoader classLoader, JavaModule module,
                                                ProtectionDomain protectionDomain) {
          return builder.visit(Advice.to(HostNameInterceptor.class).on(ElementMatchers.named("getHostName")));
        }
      };

      new AgentBuilder.Default()
          .disableClassFormatChanges()
          .ignore(new AgentBuilder.RawMatcher.ForElementMatchers(nameStartsWith("net.bytebuddy.")))
          .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
          .with(AgentBuilder.RedefinitionStrategy.REDEFINITION)
          .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
          .type(ElementMatchers.is(InetSocketAddress.class))
          .transform(hostNameTransformer)
          .installOn(instrumentation);

      // intercept InetAddress::getCanonicalHostName & InetAddress:getHostName
      AgentBuilder.Transformer canoicalHostNameTransformer = new AgentBuilder.Transformer() {
        @Override
        public DynamicType.Builder<?> transform(DynamicType.Builder<?> builder,
                                                TypeDescription typeDescription,
                                                ClassLoader classLoader, JavaModule module,
                                                ProtectionDomain protectionDomain) {
          return builder.visit(Advice.to(CanonicalHostNameInterceptor.class).on(ElementMatchers.named("getCanonicalHostName")))
              .visit(Advice.to(InetAddrHostNameInterceptor.class).on(ElementMatchers.named("getHostName")));
        }
      };

      new AgentBuilder.Default()
          .disableClassFormatChanges()
          .ignore(new AgentBuilder.RawMatcher.ForElementMatchers(nameStartsWith("net.bytebuddy.")))
          .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
          .with(AgentBuilder.RedefinitionStrategy.REDEFINITION)
          .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
          .type(ElementMatchers.is(InetAddress.class))
          .transform(canoicalHostNameTransformer)
          .installOn(instrumentation);
    }
  }

  public static class HostNameInterceptor {
    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static String enter(@Advice.This InetSocketAddress address) {
      if (address.getAddress() != null && address.getAddress().getHostAddress() != null) {
        return address.getAddress().getHostAddress();
      } else {
        return null;
      }
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.This InetSocketAddress address, @Advice.Origin Method origin,
                            @Advice.Enter String enter,
                            @Advice.Return(readOnly = false) String ret) {
      if (enter != null) {
        ret = enter;
      }
    }
  }

  public static class InetAddrHostNameInterceptor {
    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static String enter(@Advice.This InetAddress address) {
      return address.getHostAddress();
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.This InetAddress address, @Advice.Origin Method origin,
                            @Advice.Enter String enter,
                            @Advice.Return(readOnly = false) String ret) {
      if (enter != null) {
        ret = enter;
      }
    }
  }

  public static class CanonicalHostNameInterceptor {
    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static String enter(@Advice.This InetAddress address) {
      return address.getHostAddress();
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.This InetAddress address, @Advice.Origin Method origin,
                            @Advice.Enter String enter,
                            @Advice.Return(readOnly = false) String ret) {
      if (enter != null) {
        ret = enter;
      }
    }
  }

  /**
   * Parse the Java Agent configuration. The arguments are typically specified to the JVM as a javaagent as
   * {@code -javaagent:/path/to/agent.jar=<CONFIG>}. This method parses the {@code <CONFIG>} portion.
   *
   * @param args provided agent args
   * @param ifc  default bind interface
   * @return configuration to use for our application
   */
  public static Config parseConfig(String args, String ifc) {
    Pattern pattern = Pattern.compile(
        "^(?:((?:[\\w.-]+)|(?:\\[.+])):)?" + // host name, or ipv4, or ipv6 address in brackets
            "(\\d{1,5}):" +              // port
            "(.+)");                     // config file

    Matcher matcher = pattern.matcher(args);
    if (!matcher.matches()) {
      throw new IllegalArgumentException("Malformed arguments - " + args);
    }

    String givenHost = matcher.group(1);
    String givenPort = matcher.group(2);
    String givenConfigFile = matcher.group(3);

    int port = Integer.parseInt(givenPort);

    InetSocketAddress socket;
    if (givenHost != null && !givenHost.isEmpty()) {
      socket = new InetSocketAddress(givenHost, port);
    } else {
      socket = new InetSocketAddress(ifc, port);
      givenHost = ifc;
    }

    return new Config(givenHost, port, givenConfigFile, socket);
  }

  static class Config {
    String host;
    int port;
    String file;
    InetSocketAddress socket;

    Config(String host, int port, String file, InetSocketAddress socket) {
      this.host = host;
      this.port = port;
      this.file = file;
      this.socket = socket;
    }
  }
}
