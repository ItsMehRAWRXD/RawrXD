// EditorCLI.java
import java.util.Scanner;

public class EditorCLI {
    public static void main(String[] args) {
        EnhancedCursorIDE ide = new EnhancedCursorIDE();
        Scanner scanner = new Scanner(System.in);

        System.out.println("Enhanced Cursor IDE - Continue.dev Hub Integration");
        System.out.println("Commands: /key <provider> <key>, /switch <provider>, /complete <code>, /providers, /quit");

        while (true) {
            System.out.print("[" + ide.getActiveProvider() + "] > ");
            if (!scanner.hasNextLine()) break;
            String input = scanner.nextLine();

            if (input.equals("/quit")) break;

            if (input.startsWith("/key ")) {
                String[] parts = input.substring(5).split(" ", 2);
                if (parts.length == 2) {
                    ide.setApiKey(parts[0], parts[1]);
                    System.out.println("OK API key set for " + parts[0]);
                }
            } else if (input.startsWith("/switch ")) {
                String provider = input.substring(8);
                if (ide.hasApiKey(provider)) {
                    ide.switchProvider(provider);
                    System.out.println("OK Switched to " + provider);
                } else {
                    System.out.println("X No API key for " + provider);
                }
            } else if (input.startsWith("/complete ")) {
                String code = input.substring(10);
                ide.complete(code).thenAccept(result -> System.out.println("AI: " + result));
            } else if (input.equals("/providers")) {
                System.out.println("Available: " + String.join(", ", ide.getProviders()));
                for (String provider : ide.getProviders()) {
                    System.out.println("  " + (ide.hasApiKey(provider) ? "OK" : "X") + " " + provider);
                }
            }
        }

        ide.shutdown();
        System.out.println("Goodbye!");
    }
}
