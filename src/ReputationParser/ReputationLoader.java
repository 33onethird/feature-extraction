package ReputationParser;

import java.util.HashSet;
import java.util.regex.Pattern;

/**
 * This class calls all the parsers to load the Reputation DB
 *
 * @author Philipp Adam
 */
public class ReputationLoader {
	private final String MALCODEIPS ="ReputationDBs/malcode ips.txt";
	private final String MALCODEDOMAINS ="ReputationDBs/malcode domains.txt";
	private final String MALWAREDOMAINSCOM ="ReputationDBs/malwaredomains.com.txt";
	private final String MALWAREHOSTS ="ReputationDBs/malwarehosts.txt";
	private final String RANSOMTRACKERDOMAIN ="ReputationDBs/ransomtracker domain.txt";
	private final String RANSOMTRACKERIP ="ReputationDBs/ransomtracker ip.txt";
	private final String RANSOMTRACKERURL ="ReputationDBs/ransomtracker url.txt";
	
	private final Pattern MALCODEDOMAINSPATTERN = Pattern.compile("PRIMARY (.+) ");
	private final Pattern MALWAREHOSTSPATTERN = Pattern.compile("127\\.0\\.0\\.1  (.+)");
	public ReputationLoader(HashSet<String> maliciousURLs) {
		
		new RegexParser(maliciousURLs,MALCODEDOMAINSPATTERN,MALCODEDOMAINS);
	 	new RegexParser(maliciousURLs,MALWAREHOSTSPATTERN,MALWAREHOSTS);
		new SimpleParser(maliciousURLs, MALCODEIPS);
		new SimpleParser(maliciousURLs,MALWAREDOMAINSCOM);
		new SimpleParser(maliciousURLs, RANSOMTRACKERDOMAIN);
		new SimpleParser(maliciousURLs, RANSOMTRACKERIP);
		new SimpleParser(maliciousURLs, RANSOMTRACKERURL);
		new PhishtankParser(maliciousURLs);
	}
}
