package burp;

import java.util.Optional;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public final class Config {

    public static final String URL = "url";
    public static final String FORMAT = "format";

    private Options options;
    private HelpFormatter formatter = new HelpFormatter();

   // Contains options given by command line argument
    private CommandLine cmd;



    // Initializing new config for command line argument
    public Config(String[] commandLineArguments) throws ParseException {
        options = createOptions();
        cmd = doParseArgs(options, commandLineArguments);
    }


    // Returns true if the command line argument was already set
    public boolean containsOptions(String option) {
        return cmd.hasOption(option);
    }

   // Returns value of command line arguments
    public Optional<String> getOption(String option) {
        return Optional.ofNullable(cmd.getOptionValue(option));
    }

    // Printing help message
    public void printHelp() {
        formatter.printHelp("java -jar <file>", options);
    }

    // Predefined function to parse arguments
    private CommandLine doParseArgs(Options opts, String[] commandLineArguments) throws ParseException {
        CommandLineParser parser = new DefaultParser();
        return parser.parse(opts, commandLineArguments);
    }


    // Command line option
    private Options createOptions() {
        Options opts = new Options();
        opts.addOption("u", URL, true, "URL to spider");
        opts.addOption("f", FORMAT, true, "Format of report. Available values are HTML and XML.");
        return opts;
    }

}
