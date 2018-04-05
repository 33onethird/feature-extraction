package Main;
import java.io.File;
import java.util.concurrent.BlockingQueue;

/**
 * This thread is responsible for adding files to a queue for processing
 *
 * @author Philipp Adam
 */
public class FileQueuer implements Runnable {

	private String directory;
	private BlockingQueue<File> queue;

	public FileQueuer(String filePath, BlockingQueue<File> queue) {
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