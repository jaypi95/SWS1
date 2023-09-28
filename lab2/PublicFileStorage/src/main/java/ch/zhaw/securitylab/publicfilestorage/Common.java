package ch.zhaw.securitylab.publicfilestorage;

public class Common {
    
    // Server port
    public static final int PORT = 4567;
    
    // Supported reqiests
    public static final String GET = "GET";
    public static final String PUT = "PUT";
    public static final String SYSTEM = "SYSTEM";

    // Status messages
    public static final String OK = "OK";
    public static final String NOK = "NOK";
    
    // Control lines
    public static final String CONTENT = "-----CONTENT-----";
    public static final String DONE = "-----DONE-----";
    
    // The command to get disk usage
    public static final String COMMAND_USAGE = "USAGE";
}