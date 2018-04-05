package SmaliWorker;
import java.io.File;
import java.util.concurrent.BlockingQueue;

/**
 * This thread is responsible for adding .smali files to the smali analyzation
 * queue.
 *
 * @author Philipp Adam
 */
public class SmaliProducer implements Runnable {

	private String directory;
	private BlockingQueue<File> queue;

	public SmaliProducer(String filePath, BlockingQueue<File> queue) {
		this.directory = filePath;
		this.queue = queue;
	}

	@Override
	public void run() {
		try {
			listAndAddFiles(directory);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void listAndAddFiles(String dirName) throws InterruptedException {
		File[] fList = new File(dirName).listFiles();
		for (File file : fList) {
			if (file.isFile()) {
				queue.put(file);
			} else if (file.isDirectory()) {
				listAndAddFiles(file.getAbsolutePath());
			}
		}

	}

}