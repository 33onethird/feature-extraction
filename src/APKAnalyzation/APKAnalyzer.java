package APKAnalyzation;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import Main.FeatureExtractor;
import SmaliWorker.SmaliController;

/**
 * This thread organizes the analyzation of an unpacked APK
 *
 * @author Philipp Adam
 */
public class APKAnalyzer implements Runnable {
	private File XMLManifest;
	private File smaliDir;
	private File featureFile;
	private ResultCollector results;
	private Path fileLocation;
	private File output;
	private HashMap<String, String> permissionMap;
	private Set<String> suspCallTemplate;
	private BlockingQueue<File> queue;

	public APKAnalyzer(BlockingQueue<File> input, File output, HashMap<String, String> permissionMap,
			Set<String> suspCallTemplate) {
		this.queue = input;
		this.output = output;
		this.permissionMap = permissionMap;
		this.suspCallTemplate = suspCallTemplate;
	}

	public static String byteToHex(byte b) {
		int i = b & 0xFF;
		return Integer.toHexString(i);
	}

	@Override
	/**
	 * Pulls a packed APK from the queue and creates new instances of
	 * ManifestAnalyzer and SmaliController.
	 */
	public void run() {
		while (true) {
			File input = queue.poll();

			if (input == null && !FeatureExtractor.isPackedProducerAlive()) {
				System.out.println("No more to analyze");
				return;
			}

			boolean unpackSuccess = true;

			if (input != null) {
				File unpackedAPK = new File(input.getName());
				try {
					Process proc = Runtime.getRuntime().exec("java -jar apktool.jar d -o " + unpackedAPK + " " + input);
					if (!proc.waitFor(300, TimeUnit.SECONDS)) {
						// timeout - kill the process.
						unpackSuccess = false;
						proc.destroy();
						System.out.println("TIMEOUT");
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
				if (unpackSuccess) {

					System.out.println("ANALYZING " + input.getName());
					unpackedAPK = new File(input.getName());
					XMLManifest = new File(unpackedAPK + "/AndroidManifest.xml");
					smaliDir = new File(unpackedAPK + "/smali");
					featureFile = new File(output + "/" + input.getName() + ".txt");
					results = new ResultCollector(featureFile, unpackedAPK);
					fileLocation = Paths.get(input.getAbsolutePath());

					try {
						if(FeatureExtractor.UseJanus()) {
						// Check the first 4 bytes if they do not indicate a Zip file it may be a janus
						// exploit
						// https://www.guardsquare.com/en/blog/new-android-vulnerability-allows-attackers-modify-apps-without-affecting-their-signatures
						byte[] data = Files.readAllBytes(fileLocation);
						String byte0 = byteToHex(data[0]);
						String byte1 = byteToHex(data[1]);
						String byte2 = byteToHex(data[2]);
						String byte3 = byteToHex(data[3]);
						System.out.println("First 4 bytes:" + byte0 + "|" + byte1 + "|" + byte2 + "|" + byte3);
						if (!byte0.equals("50") || !byte1.equals("4b") || !byte2.equals("3") || !byte3.equals("4")) {
							results.setJanus();
							System.out.println("INVALID ZIP FILE - Janus exploit?");
						}

						}
						new ManifestAnalyzer(XMLManifest, results);
						new SmaliController(smaliDir.getCanonicalPath(), permissionMap, suspCallTemplate, results);

					} catch (Exception e) {
						e.printStackTrace();
					}

				}
			}

		}

	}
}
