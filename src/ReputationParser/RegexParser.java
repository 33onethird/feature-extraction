package ReputationParser;
import java.io.File;
import java.util.HashSet;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
/**
 * The RegexParser tries to match every line with a regex and adds the match to the Reputation Db
 *
 * @author Philipp Adam
 */
public class RegexParser {
	
	private   Pattern pattern; 
	
	public RegexParser(HashSet<String> urls, Pattern regex, String file) {
		File f = new File(file);
		pattern=regex;
		Matcher regexmatcher;
		if (f.exists()) {
			try {
				Scanner scanner = new Scanner(f);
				while (scanner.hasNextLine()) {
					String lineFromFile=scanner.nextLine();
					regexmatcher = pattern.matcher(lineFromFile);
					if (regexmatcher.find()) {
						urls.add(regexmatcher.group(1));
					}
				}
				scanner.close();
			}catch(Exception e) {
				
			}
			
		}
	}

}
