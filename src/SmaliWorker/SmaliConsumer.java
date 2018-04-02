package SmaliWorker;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import APKAnalyzation.ResultCollector;

/**
 * This thread takes a file of decompiled code from the queue and analyzes it
 * for its features. The results are passed to its ResultCollector.
 * 
 * @author Philipp Adam
 * @version 2.0 12/2/18
 */
public class SmaliConsumer implements Runnable {
	// Regex patterns for URLs
	public final static Pattern urlPattern = Pattern.compile("const-string .+(http:\\/\\/.+)\"");
	public final static Pattern domainPattern = Pattern.compile("http:\\/\\/(.+\\..*?)\\/.+");
	public final static Pattern urlHTTPSPattern = Pattern.compile("const-string .+(https:\\/\\/.+)\"");
	public final static Pattern domainHTTPSPattern = Pattern.compile("https:\\/\\/(.+\\..*?)\\/.+");
	// Regex for details on Cipher
	public final static Pattern cipherPattern = Pattern.compile("const-string.*\\\"(.*)\\\"");

	private Set<String> suspCallSet;
	private Set<String> apiCalls = new HashSet<String>();
	private Set<String> calls = new HashSet<String>();
	private Set<String> url = new HashSet<String>();
	private Set<String> realPermission = new HashSet<String>();
	private HashMap<String, String> permissionMap;
	private ResultCollector results;
	private SmaliController controller;
	private BlockingQueue<File> queue;

	public SmaliConsumer(BlockingQueue<File> queue, HashMap<String, String> prebuiltPermissionMap,
			Set<String> prebuiltSuspCallTemplate, ResultCollector results, SmaliController smaliController) {
		this.queue = queue;
		this.permissionMap = prebuiltPermissionMap;
		suspCallSet = prebuiltSuspCallTemplate;
		this.results = results;
		this.controller = smaliController;
	}

	/**
	 * Pulls a .smali file from the queue until there are no more files in the queue
	 * and the producer terminated. Analyzed features are: apiCalls, calls, URLS and
	 * realPermissions.
	 */
	public void run() {
		while (true) {
			try {
				File file = queue.poll();

				if (file == null && !controller.isProducerAlive()) { // no more to process
					for (String call : apiCalls) {
						call = call.substring(10);// omit api_call::
						if (permissionMap.containsKey(call)) {
							for (String permission : splitToList(permissionMap.get(call))) { // if a call requires more
																								// than one
																								// permission, split the
																								// string
																								// to an iterable list
								realPermission.add("real_permission::" + permission);
							}
						}
					}
					results.addAPICALLSResults(apiCalls);
					results.addCALLSResults(calls);
					results.addURLResults(url);
					results.addREALPERMISSIONResults(realPermission);
					results.consumerFinished();
					// System.out.println(Thread.currentThread().getName()+" finished");
					return;
				}

				Matcher URLMatcher;
				Matcher domainMatcher;
				Matcher URLHTTPSMatcher;
				Matcher domainHTTPSMatcher;
				Matcher cipherMatcher;
				String previous = "";

				if (file != null) {
					Scanner scanner = new Scanner(file);
					while (scanner.hasNextLine()) {
						final String lineFromFile = scanner.nextLine();
						if (lineFromFile.contains("invoke")) { // Ignore all none-invoke lines
							for (String call : permissionMap.keySet()) {
								if (lineFromFile.contains(call)) { // If the current call has not been found in the app
																	// already and is found in this line
									apiCalls.add("api_call::" + call);
									// System.out.println(call);
									break;
								}
							}
						}
						if (!lineFromFile.equals("")) {
							for (String suspCall : suspCallSet) {
								if (lineFromFile.contains(suspCall)) { // If the current line contains a suspicious api
																		// call
									if (lineFromFile.contains("Cipher")) { // If it is a cipher, look at the previous
																			// line
																			// to get more information e.g.
																			// Cipher(RSA/ECB/PKCS1Padding)
										cipherMatcher = cipherPattern.matcher(previous);
										if (cipherMatcher.find()) {
											calls.add("call::Cipher(" + cipherMatcher.group(1) + ")");
										}
									} else {
										calls.add("call::" + suspCall);
									}
									break;
								}

							}
						}

						if (lineFromFile.contains("const-string")) {
							URLMatcher = urlPattern.matcher(lineFromFile);
							domainMatcher = domainPattern.matcher(lineFromFile);
							URLHTTPSMatcher = urlHTTPSPattern.matcher(lineFromFile);
							domainHTTPSMatcher = domainHTTPSPattern.matcher(lineFromFile);
							if (URLMatcher.find()) {
								url.add("url::" + URLMatcher.group(1));
							}
							if (domainMatcher.find()) {
								url.add("url::" + domainMatcher.group(1));
							}
							if (URLHTTPSMatcher.find()) {
								url.add("url::" + URLHTTPSMatcher.group(1));
							}
							if (domainHTTPSMatcher.find()) {
								url.add("url::" + domainHTTPSMatcher.group(1));
							}
						}

						previous = lineFromFile;

					}
					scanner.close();
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	/**
	 * Convenience method to split a string of many permissions to a list e.g.
	 * "android.permission.INTERNET-android.permission.RECEIVE_BOOT_COMPLETED" to
	 * [android.permission.INTERNET,android.permission.RECEIVE_BOOT_COMPLETED]
	 *
	 * @param string
	 *            the string to split
	 * @return result list of permissions
	 */
	private ArrayList<String> splitToList(String string) {
		ArrayList<String> result = new ArrayList<String>();
		while (true) {
			if (string.contains("-")) {
				result.add(string.split("-", 2)[0]);
				string = string.split("-", 2)[1];
			} else {
				result.add(string);
				break;
			}
		}
		return result;
	}
}