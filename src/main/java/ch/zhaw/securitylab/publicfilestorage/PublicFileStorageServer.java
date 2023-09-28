package ch.zhaw.securitylab.publicfilestorage;

import java.io.*;
import java.net.*;
import java.util.Scanner;
import static ch.zhaw.securitylab.publicfilestorage.Common.*;

public class PublicFileStorageServer {
    
    // The directory that contains the files
    private static final String FILES_DIR = "files/";
    
    // The socket used to listen for incoming connections from clients
    private static ServerSocket listeningSocket;
    
    /* Constructor */
    public PublicFileStorageServer() {
        try {
            listeningSocket = new ServerSocket(PORT);
        } catch (IOException e) {
            // If server socket cannot be created, exit
            System.out.println("ServerSocket cannot be created, exiting");
            System.exit(-1);
        }
    }

    /* This method starts the actual file server */
    private void run() {
        while (true) {
            
            // Wait for a connection from a client and process the request
            try {
                Socket socket = listeningSocket.accept();
                processRequest(socket);
                socket.close();
            } catch (IOException e) {
                // If accepting connections does not work, exit
                System.out.println("Connections cannot be accepted, exiting");
                System.exit(-1);
            }
        }
    }
    
    private boolean validateFirstLineOfRequest(String input) {
        if (input != null && input.matches(
            "^(GET|PUT|SYSTEM) [\\x21-\\x7E][\\x20-\\x7E]*$")){
            return true;
        }
        return false;
    }
        private boolean validateFilename(String filename){
        if (filename != null && filename.matches(
            "^(?!(?:..%2F)+)[a-zA-Z0-9_+=$%?,.;:]{1,100}$")){
            return true;
        }
        return false;
    }
        
    private boolean validateCommand(String command){
        if (command != null && command.matches(
            "^(?!.*;\\s)[\\x20-\\x3A\\x3C-\\x7E]+$")){
            return true;
        }
        return false;
    }
    
    private String readLineMaxChar(Reader reader, int max) throws IOException {
        StringBuilder bobTheBuilder = new StringBuilder();
        int totalCharactersRead = 0;
        int charRead;

        while ((charRead = reader.read()) != -1 && totalCharactersRead < max) {
            char character = (char) charRead;
                        if (character == '\n') {
                // Stop reading if a newline character is encountered.
                break;
            }
            bobTheBuilder.append(character);
            totalCharactersRead++;


        }
        return bobTheBuilder.toString();
    }

    
         
    /* Reads the request from the client and responds accordingly */
    private void processRequest(Socket socket) {

        // fromClient and toClient are used to read data from and write data to the client
        try (BufferedReader fromClient = new BufferedReader(
                new InputStreamReader(socket.getInputStream()));
             OutputStreamWriter toClient = new OutputStreamWriter(socket.getOutputStream())) {
                
            // Read first line of request from the client
            String line;
            try{
               line = readLineMaxChar(fromClient, 1000);
               
            } catch (IOException e){
                writeNOKNoContent(toClient);
                return;
            }
            if (line == null) {
                // Apparently, the client disconnected without sending anything, do nothing
            } else {
                System.out.println("First line of request: " + line);
                //Validate the first line of the request
                if(!validateFirstLineOfRequest(line)){
                    writeNOKNoContent(toClient);
                    return;
                }
                // Get request type and argument from the first line of the request
                int indexSpace = line.indexOf(' ');
                String requestType = line.substring(0, indexSpace);
                String argument = urlDecode(line.substring(indexSpace + 1));
                switch (requestType) {
                    case GET:
                        serveFile(toClient, argument);
                        break;
                    case PUT:
                        storeFile(fromClient, toClient, argument);
                        break;
                    case SYSTEM:
                        executeSystemCommand(toClient, argument);
                        break;
                    default:
                        // Unsupported request type, respond with NOK
                        writeNOKNoContent(toClient);
                        break;
                }
            }
        } catch (IOException e) {
            // An IO problem happened, ignore (stop handling request)
        }
    }
    

    /* serveFile is used to return the content of a requested file */
    private void serveFile(OutputStreamWriter toClient, String filename) {
        if(!validateFilename(filename)){
            writeNOKNoContent(toClient);
            return;
        }
        // Read lines from file and send them to the client
        String filepath = FILES_DIR + filename;
        try (BufferedReader fromFile = new BufferedReader(new FileReader(filepath))) {
            writeOKContent(toClient);
            String line = fromFile.readLine();
            while (line != null) {
                toClient.write(line + "\n");
                line = fromFile.readLine();
            }
            toClient.write(DONE + "\n");
        } catch (IOException e) {
            writeNOKNoContent(toClient);
        }
    }

    /* storeFile is used to store a file */
    private void storeFile(BufferedReader fromClient, OutputStreamWriter toClient,
            String filename) {
        if(!validateFilename(filename)){
            writeNOKNoContent(toClient);
            return;
        }
        try {
            // Read lines from client and write them to the specified file
            try{
               readLineMaxChar(fromClient, 1000);        
            } catch (IOException e){
                writeNOKNoContent(toClient);
                return;
            } // Absorb CONTENT control line
            StringBuilder fileContent = new StringBuilder();
            String line;
            try{
               line = readLineMaxChar(fromClient, 1000);        
            } catch (IOException e){
                writeNOKNoContent(toClient);
                return;
            }
            while ((line != null) && (!line.equals(DONE))) {
                if(fileContent.length() <= 10000){
                    fileContent.append(line).append("\n");
                } else {
                    writeNOKNoContent(toClient);
                    return;
                }
                try{               
                    line = readLineMaxChar(fromClient, 1000);        
                } catch (IOException e){
                    writeNOKNoContent(toClient);
                    return;
                }
            }
            String filepath = FILES_DIR + filename;
            try (FileWriter toFile = new FileWriter(filepath)) {
                toFile.write(fileContent.toString());
            }
            writeOKNoContent(toClient);
        } catch (IOException e) {
            writeNOKNoContent(toClient);
        }
    }
        
    /* Execute a command and return results to client */
    private void executeSystemCommand(OutputStreamWriter toClient, String command) {
        if(!validateCommand(command)){
            writeNOKNoContent(toClient);
            return;
        }
        
        try {
            // Depending on the actual command, execute the right OS command
            command = command;
            int indexSpace = command.indexOf(' ');
            String actualCommand = command.substring(0, indexSpace);
            String options = command.substring(indexSpace + 1);
            if (actualCommand.equals(COMMAND_USAGE)) {
                Runtime runtime = Runtime.getRuntime();
                String[] cmd = new String[3];
                cmd[0] = "/bin/sh";
                cmd[1] = "-c";
                cmd[2] = "du -h " + FILES_DIR + options;
                Process proc = runtime.exec(cmd);
                Scanner reader = new Scanner(proc.getInputStream());
                writeOKContent(toClient);
                while (reader.hasNextLine()) {
                    toClient.write(reader.nextLine() + "\n");
                }
                toClient.write(DONE + "\n");
            } else {
                writeNOKNoContent(toClient);
            }
        } catch (IOException e) {
            writeNOKNoContent(toClient);
        }
    }

    /* Send an OK message without additional content to the client */
    private void writeOKNoContent(OutputStreamWriter toClient) {
        try {
            toClient.write(OK + "\n" + DONE + "\n");
        } catch (IOException e) {
            // ignore
        }
    }
    
    /* Send a NOK message without additional content to the client */
    private void writeNOKNoContent(OutputStreamWriter toClient) {
        try {
            toClient.write(NOK + "\n" + DONE + "\n");
        } catch (IOException e) {
            // ignore
        }
    }
 
    /* Send an OK message with a CONTENT separator to the client */
    private void writeOKContent(OutputStreamWriter toClient) {
        try {
            toClient.write(OK + "\n" + CONTENT + "\n");
        } catch (IOException e) {
            // ignore
        }
    }

    /* URL-decode input */
    private String urlDecode(String input) {
        try {
            input = URLDecoder.decode(input, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            // Returns non-decoded input
        }
        return input;
    }

    /* main method */
    public static void main(String argv[]) {

        // Create a PublicFileStorageServer object and run it
        (new PublicFileStorageServer()).run();
    }
}