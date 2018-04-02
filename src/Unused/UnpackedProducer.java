package Unused;

import java.io.File;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import Main.FeatureExtractor;

/**
 * This thread is responsible for unpacking APKs and adding the unpacked
 * directories to the unpackedAPKs queue.
 * 
 * Currently unused
 *
 * @author Philipp Adam
 * @version 2.0 12/2/18
 */
public class UnpackedProducer implements Runnable {

	private BlockingQueue<File> packedQueue;
	private BlockingQueue<File> unpackedQueue;

	public UnpackedProducer(BlockingQueue<File> packedQueue, BlockingQueue<File> unpackedAPKs) {
		this.packedQueue = packedQueue;
		this.unpackedQueue = unpackedAPKs;
	}

	@Override
	public void run() {
		while (true) {
			File apk = packedQueue.poll();
			boolean unpackSuccess = true;
			if (apk == null && !FeatureExtractor.isPackedProducerAlive()) {
				System.out.println("No more to unpack");
				return;
			}

			if (apk != null) {
				File unpackedAPK = new File(apk.getName());
				try {
					Process proc = Runtime.getRuntime().exec("java -jar apktool.jar d -o " + unpackedAPK + " " + apk);
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
					unpackedQueue.add(unpackedAPK);
				}
			}

		}

	}

}