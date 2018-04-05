package LibScout;

import java.io.File;
/**
 * This thread is responsible for starting LibScout with the correct parameters
 *
 * @author Philipp Adam
 */
public class LibScoutAnalyzer implements Runnable {

	private final static String LIBSCOUT = "LibScout.jar";
	private final static String SDK = "android-23.jar";
	private final static String PROFILES = "profiles";
	private String outputdir;
	private File inputdir;

	public LibScoutAnalyzer(File input, String outputdir) {
		inputdir = input;
		this.outputdir = outputdir;
	}

	@Override
	public void run() {
		if (inputdir.isDirectory()) {
			try {
				Process proc = Runtime.getRuntime().exec("java -jar " + LIBSCOUT + " -o match -a " + SDK + " -p "+ PROFILES + " -d " + outputdir + " "+inputdir);
				proc.waitFor();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
			System.out.println("---------------LIBSCOUT ANALYSIS COMPLETE -------------------");
	}

}
