package LibScout;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.concurrent.BlockingQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import Main.FeatureExtractor;
/**
 * This thread parses the logfiles from LibScout and merges them with the existing feature vector files
 *
 * @author Philipp Adam
 */
public class LibScoutParser implements Runnable {
	public final static Pattern heuristicPattern = Pattern.compile("Found lib root package (.+)");
	public final static Pattern matchNamePattern = Pattern.compile("name: (.+)");
	public final static Pattern matchVersionPattern = Pattern.compile("version: (.+)");
	public final static Pattern matchPackagePattern = Pattern.compile("lib root package: (.+)");
	private BlockingQueue<File> queue;
	private File output;

	public LibScoutParser(BlockingQueue<File> libScoutresultFiles, File output) {
		queue = libScoutresultFiles;
		this.output = output;
	}

	@Override
	public void run() {
		Matcher regexmatcher;
		while (true) {
			File input = queue.poll();

			if (input == null && !FeatureExtractor.isResultQueuerAlive()) {
				System.out.println("No more to parse");
				return;
			}
			if (input != null && input.isFile()) {
				ArrayList<String> heuristics = new ArrayList<String>();
				ArrayList<String> matches = new ArrayList<String>();
				ArrayList<String> partialMatches = new ArrayList<String>();
				try {
					Scanner scanner = new Scanner(input);
					while (scanner.hasNextLine()) {
						String lineFromFile = scanner.nextLine();
						if (lineFromFile.contains("Found lib root package")) { // heuristics
							regexmatcher = heuristicPattern.matcher(lineFromFile);
							if (regexmatcher.find()) {
								// System.out.println("LibScout heuristic::"+regexmatcher.group(1));
								heuristics.add("LibScout heuristic::" + regexmatcher.group(1));
							}
						}
						if (lineFromFile.contains("ProfileMatch") && lineFromFile.contains("name:")) { // full matches
							String name = "";
							String version = "";
							String rootPackage = "";

							regexmatcher = matchNamePattern.matcher(lineFromFile);
							if (regexmatcher.find()) {
								name = regexmatcher.group(1);
							}
							scanner.nextLine(); // Skip category:
							lineFromFile = scanner.nextLine(); // get version
							regexmatcher = matchVersionPattern.matcher(lineFromFile);
							if (regexmatcher.find()) {
								version = regexmatcher.group(1);
							}
							scanner.nextLine(); // Skip release-date:
							lineFromFile = scanner.nextLine(); // get package
							regexmatcher = matchPackagePattern.matcher(lineFromFile);
							if (regexmatcher.find()) {
								rootPackage = regexmatcher.group(1);
							}
							// System.out.println("LibScout match::"+name+" "+rootPackage+" "+version);
							matches.add("LibScout match::" + name + " " + rootPackage + " " + version);
						}

						if (lineFromFile.contains("LibraryIdentifier") && lineFromFile.contains("name:")
								&& !lineFromFile.contains("Package name:")) { // Partial matches
							String name = "";
							String version = "";
							String rootPackage = "";

							regexmatcher = matchNamePattern.matcher(lineFromFile);
							if (regexmatcher.find()) {
								name = regexmatcher.group(1);
							}
							scanner.nextLine(); // Skip category:
							lineFromFile = scanner.nextLine(); // get version
							regexmatcher = matchVersionPattern.matcher(lineFromFile);
							if (regexmatcher.find()) {
								version = regexmatcher.group(1);
							}
							scanner.nextLine(); // Skip release-date:
							lineFromFile = scanner.nextLine(); // get package
							regexmatcher = matchPackagePattern.matcher(lineFromFile);
							if (regexmatcher.find()) {
								rootPackage = regexmatcher.group(1);
							}
							// System.out.println("LibScout partialmatch::"+name+" "+rootPackage+"
							// "+version);
							partialMatches.add("LibScout partialmatch::" + name + " " + rootPackage + " " + version);
						}

					}
					scanner.close();
				} catch (Exception e) {
					e.printStackTrace();
				}
				String featureFilePath = output + "/" + input.getName().replace(".log", ".apk") + ".txt";
				System.out.println("Merging " + featureFilePath + " with LibScout findings");
				File featureFile = new File(featureFilePath);
				if (featureFile.exists()) {
					AppendToFile(featureFile, heuristics);
					AppendToFile(featureFile, matches);
					AppendToFile(featureFile, partialMatches);
				}

			}

		}

	}

	
	private void AppendToFile(File featureFile, ArrayList<String> arraylist) {
		FileWriter fw;
		BufferedWriter bw;
		try {
			fw = new FileWriter(featureFile.getCanonicalPath(), true);
			bw = new BufferedWriter(fw);
			for (String s : arraylist) {
				bw.write(s);
				bw.newLine();
				bw.flush();
			}
			bw.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
