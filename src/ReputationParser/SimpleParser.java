package ReputationParser;
import java.io.File;
import java.util.HashSet;
import java.util.Scanner;
/**
 * The SimpleParser loads every line as an entry to the Reputation DB
 *
 * @author Philipp Adam
 */
public class SimpleParser {

	public SimpleParser(HashSet<String> urls, String file) {
		File f = new File(file);
		if (f.exists()) {
			try {
				Scanner scanner = new Scanner(f);
				while (scanner.hasNextLine()) {
					urls.add(scanner.nextLine());
				}
				scanner.close();
			}catch(Exception e) {
				
			}
			
		}
	}

}
