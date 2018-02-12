import java.io.File;
import java.util.concurrent.BlockingQueue;

/**
 * This thread is responsible for adding packed APKs from the input directory to
 * the queue of packed APKs
 *
 * @author Philipp Adam
 * @version 2.0 12/2/18
 */
public class PackedProducer implements Runnable {

	private String directory;
	private BlockingQueue<File> queue;

	public PackedProducer(String filePath, BlockingQueue<File> queue) {
		this.directory = filePath;
		this.queue = queue;
	}

	@Override
	public void run() {
		File[] fList = new File(directory).listFiles();
		for (File file : fList) {
			if (file.isFile()) {
				try {
					queue.put(file);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}

	}

}