package edu.arapahoe;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.Normalizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class Main {

    public static void main(String[] args) {

        //ERRORO1-J
        // Check argument
        if (args.length == 0) {
            System.out.println("Invalid file.");
            return;
        }
        // IDS50-J the filename that we are reading does not contain any malicious characters,
        // but it is not checking for it
        Pattern filePattern = Pattern.compile("[*?|<>/:\\\\]");
        String filename = Normalizer.normalize(args[0], Normalizer.Form.NFKC);
        Matcher fileBlacklist = filePattern.matcher(args[0]);


        if (fileBlacklist.find()) {
            throw new IllegalArgumentException("Bad Filename");
        }

        //FIO16-J
        try {
            // Define base directory (allowed directory)
            File baseDir = new File("C:\\homepath").getCanonicalFile();

            // Build requested file path
            File requestedFile = new File(baseDir, args[0]).getCanonicalFile();

            // Ensure file stays inside allowed directory
            if (!requestedFile.getPath().startsWith(baseDir.getPath())) {
                System.out.println("Invalid file.");
                return;
            }

            // Open and read file safely
            try (BufferedReader reader =
                         new BufferedReader(new FileReader(requestedFile))) {

                System.out.println("Email Addresses:");

                String line;
                while ((line = reader.readLine()) != null) {
                    // IDS01-J
                    // There was originally no normalization of input
                    // we need to normalize the string "fileLine" that is being read
                    String fileLine = Normalizer.normalize(line, Normalizer.Form.NFKC);
                    // NFKC Format will convert the string into its canonicalized form,
                    // so it will not be in am ambiguous form

                    // passes the fileLine into a function to check if the email is real
                    Boolean email = validEmail(fileLine);

                    // if the email passes the tests in validEmail, print the out the email.
                    if (email == true) {
                        System.out.println(fileLine);
                    }

                    // once normalized, we will validate the input and check for malicious characters <, >
                    // also after normalizing, we will validate the string by checking for proper email formatting
                    //Pattern scriptPattern = Pattern.compile("[<>]");
                    //Matcher scriptMatcher = scriptPattern.matcher(fileLine);
                    //^^This is being handled by the regex validator
                }
            }
        } catch (IOException e) {
            // Generic error message only (ERR01-J compliant)
            System.out.println("Invalid file.");
        }
    }
    //
    //creates the filter to check for allowed characters
    //first part applies to the username
    //second half applies to the domain
    //third applies to final part of the domain (.edu, .com, etc)
    public static boolean validEmail(String email) {
        Pattern EMAIL_PATTERN = Pattern.compile("[a-z0-9._%+-]+" + "@[a-z0-9.-]+\\.[a-z]{2,3}", Pattern.CASE_INSENSITIVE);
        Matcher matcher;


        // checks for some cases not contained in the regex, then returns false if the email fails them
        if (email == null || email.contains("..") || email.startsWith(".")){
            return false;
        }

        // Checks the string against the matcher and returns true or false.
        matcher = EMAIL_PATTERN.matcher(email);
        return matcher.matches();
    }
}

