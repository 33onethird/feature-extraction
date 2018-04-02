package SmaliWorker;
import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;

import APKAnalyzation.ResultCollector;

/**
 * Organizes the analyzation of decompiled code per APK file. Creates multiple
 * SmaliConsumer instances, which analyze the files.
 *
 * @author Philipp Adam
 * @version 2.0 12/2/18
 */
public class SmaliController {

	private final int NUMBER_OF_CONSUMERS = 4;
	private final int QUEUE_SIZE = 100;

	private HashMap<String, String> permissionMap; // Datastructure mapping MethodCalls <-> Permission(s)
	private Set<String> suspCallTemplate = new HashSet<String>(); // Datastructure containing a list of
																	// suspicious calls
	private BlockingQueue<File> queue;
	private Collection<Thread> producerThreadCollection, allThreadCollection;
	private ResultCollector results;
	private String smalidir;

	public SmaliController(String file, HashMap<String, String> mappingfile, Set<String> apicalls,
			ResultCollector results) {
		producerThreadCollection = new ArrayList<Thread>();
		allThreadCollection = new ArrayList<Thread>();
		queue = new LinkedBlockingDeque<File>(QUEUE_SIZE);
		this.results = results;
		this.results.setConsumers(NUMBER_OF_CONSUMERS);
		permissionMap = mappingfile;
		suspCallTemplate = apicalls;
		this.smalidir = file;

		createAndStartProducers();
		createAndStartConsumers();

		for (Thread t : allThreadCollection) {
			try {
				t.join();
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		System.out.println("SMALIController finished");
	}

	/**
	 * Creates a new instance of SmaliProducer, which adds the files of decompiled
	 * code to the analyzation queue.
	 */
	private void createAndStartProducers() {
		SmaliProducer producer = new SmaliProducer(smalidir, queue);
		Thread producerThread = new Thread(producer, "APK");
		producerThreadCollection.add(producerThread);
		producerThread.start();
		allThreadCollection.addAll(producerThreadCollection);
	}
	/**
	 * Creates several new instances of SmaliConsumer, which analyzes files from
	 * the analyzation queue and reports the findings to the ResultCollector
	 */
	private void createAndStartConsumers() {
		for (int i = 0; i < NUMBER_OF_CONSUMERS; i++) {
			Thread consumerThread = new Thread(new SmaliConsumer(queue, permissionMap, suspCallTemplate, results, this),
					"consumer-" + i);
			allThreadCollection.add(consumerThread);
			consumerThread.start();
		}
	}
	/**
	 * Called from SmaliConsumer, if there is more to analyze 
	 * 
     * @return If there is more to analyze
	 */
	public boolean isProducerAlive() {
		for (Thread t : producerThreadCollection) {
			if (t.isAlive())
				return true;
		}
		return false;
	}

}