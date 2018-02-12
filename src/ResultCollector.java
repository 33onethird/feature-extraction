import java.io.File;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;

/**
 * This class collects the findings from ManifestAnalyzer and SmaliConsumer and
 * writes the results to the output directory if all SmaliConsumer threads are
 * finished
 *
 * @author Philipp Adam
 * @version 2.0 12/2/18
 */
public class ResultCollector {
	private boolean janus = false;
	private Set<String> permissions = new HashSet<String>();
	private Set<String> features = new HashSet<String>();
	private Set<String> intents = new HashSet<String>();
	private Set<String> serviceReceiver = new HashSet<String>();
	private Set<String> activity = new HashSet<String>();
	private Set<String> apiCalls = new HashSet<String>();
	private Set<String> calls = new HashSet<String>();
	private Set<String> url = new HashSet<String>();
	private Set<String> realPermission = new HashSet<String>();
	private int finishedConsumers = 0;
	private int totalConsumers;
	private PrintWriter writer;
	private File toDelete;

	public ResultCollector(File featureFile, File unpackedAPK) {
		toDelete = unpackedAPK;
		try {
			writer = new PrintWriter(featureFile, "UTF-8");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	synchronized public void setConsumers(int consumers) {
		totalConsumers = consumers;
	}

	synchronized public void addAPICALLSResults(Set<String> apiCalls) {
		this.apiCalls.addAll(apiCalls);
	}

	synchronized public void addCALLSResults(Set<String> Calls) {
		this.calls.addAll(Calls);
	}

	synchronized public void addURLResults(Set<String> url) {
		this.url.addAll(url);
	}

	synchronized public void addREALPERMISSIONResults(Set<String> realPermission) {
		this.realPermission.addAll(realPermission);
	}

	public synchronized void addACTIVITYResults(Set<String> activity) {
		this.activity = activity;
	}

	public synchronized void addFEATURESResults(Set<String> features) {
		this.features = features;
	}

	public synchronized void addPERMISSIONResults(Set<String> permissions) {
		this.permissions = permissions;
	}

	public synchronized void addINTENTSResults(Set<String> intents) {
		this.intents = intents;
	}

	public synchronized void addSERVICERECEIVERResults(Set<String> serviceReceiver) {
		this.serviceReceiver = serviceReceiver;
	}

	public synchronized void setJanus() {
		this.janus = true;
	}

	/**
	 * Called by a SmaliConsumer thread to report that it has finished. If all
	 * threads are finished, the results are written to a file.
	 *
	 * @param lines
	 *            set to write
	 */
	public synchronized void consumerFinished() {
		finishedConsumers++;
		if (finishedConsumers == totalConsumers) {
			write(activity);
			write(features);
			write(permissions);
			write(intents);
			write(serviceReceiver);
			write(apiCalls);
			write(calls);
			write(url);
			write(realPermission);
			if (janus) {
				writer.println("INVALID ZIP");
			}
			writer.flush();
			writer.close();
			deleteFolder(toDelete);
		}
	}

	/**
	 * Convenience method to write a set of features to a file
	 *
	 * @param lines
	 *            set to write
	 */
	private synchronized void write(Set<String> lines) {
		for (String line : lines) {
			writer.println(line);
		}
	}

	/**
	 * Deletes the unpacked apk after extraction
	 *
	 * @param folder
	 *            dir to delete
	 */
	public synchronized void deleteFolder(File folder) {
		File[] files = folder.listFiles();
		if (files != null) { // some JVMs return null for empty dirs
			for (File f : files) {
				if (f.isDirectory()) {
					deleteFolder(f);
				} else {
					f.delete();
				}
			}
		}
		folder.delete();
	}

}
