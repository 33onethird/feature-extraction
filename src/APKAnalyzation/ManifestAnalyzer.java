package APKAnalyzation;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * This class parses the Manifest.xml file and extracts its features.
 *
 * @author Philipp Adam
 */
public class ManifestAnalyzer {
	private Set<String> permissions = new HashSet<String>();
	private Set<String> features = new HashSet<String>();
	private Set<String> intents = new HashSet<String>();
	private Set<String> serviceReceiver = new HashSet<String>();
	private Set<String> activity = new HashSet<String>();

	/**
	 * Parses a given Manifest and passes the findings to the ResultCollector
	 *
	 * @param manifest
	 *            Manifest file
	 * @param results
	 *            Result Collector
	 */
	public ManifestAnalyzer(File manifest, ResultCollector results) {
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder;
		try {

			dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(manifest);
			doc.getDocumentElement().normalize();

			//System.out.println("PARSING FOR PERMISSIONS");

			NodeList nList = doc.getElementsByTagName("uses-permission");
			for (int temp = 0; temp < nList.getLength(); temp++) {
				Node nNode = nList.item(temp);
				Element eElement = (Element) nNode;
				permissions.add("permission::" + eElement.getAttribute("android:name"));
			}

			//System.out.println("PARSING FOR FEATURES");

			nList = doc.getElementsByTagName("uses-feature");
			for (int temp = 0; temp < nList.getLength(); temp++) {
				Node nNode = nList.item(temp);
				Element eElement = (Element) nNode;
				features.add("feature::" + eElement.getAttribute("android:name"));
			}

			//System.out.println("PARSING FOR ACTIVITIES");

			nList = doc.getElementsByTagName("activity");
			for (int temp = 0; temp < nList.getLength(); temp++) {
				Node nNode = nList.item(temp);
				Element eElement = (Element) nNode;
				if (eElement.hasAttribute("android:theme") || (eElement.hasAttribute("android:label")
						&& eElement.hasAttribute("android:screenOrientation"))) {
					activity.add("activity::" + eElement.getAttribute("android:name"));
				}

				if (nNode.hasChildNodes()) {
					NodeList children = nNode.getChildNodes();
					for (int i = 0; i < children.getLength(); i++) {
						if (children.item(i).getNodeName().equals("intent-filter")
								&& children.item(i).hasChildNodes()) {
							NodeList actions = children.item(i).getChildNodes();
							for (int j = 0; j < actions.getLength(); j++) {
								Node currenNode = actions.item(j);
								if (currenNode.getNodeName().equals("action")) {
									Element currentActionElement = (Element) currenNode;
									if (currentActionElement.getAttribute("android:name") // get the main activity of
																							// the apk
											.equals("android.intent.action.MAIN")) {
										activity.add(
												"activity::" + getLastString(eElement.getAttribute("android:name")));
									}
								}

							}
						}
					}
				}
			}

			//System.out.println("PARSING FOR INTENT-FILTERS");

			nList = doc.getElementsByTagName("intent-filter");
			for (int temp = 0; temp < nList.getLength(); temp++) {
				Node nNode = nList.item(temp);
				Element currentIntent = (Element) nNode;

				if (currentIntent.hasChildNodes()) {
					NodeList children = currentIntent.getChildNodes();

					for (int i = 0; i < children.getLength(); i++) {
						if (!children.item(i).getNodeName().equals("#text")) {

							Element child = (Element) children.item(i);
							if (child.hasAttribute("android:name")) {
								intents.add("intent::" + child.getAttribute("android:name"));
							}
						}
					}

				}

			}

			//System.out.println("PARSING FOR SERVICE_RECEIVERS");

			nList = doc.getElementsByTagName("service");
			for (int temp = 0; temp < nList.getLength(); temp++) {
				Node nNode = nList.item(temp);
				Element eElement = (Element) nNode;
				serviceReceiver.add("service_receiver::" + eElement.getAttribute("android:name"));
			}
			nList = doc.getElementsByTagName("receiver");
			for (int temp = 0; temp < nList.getLength(); temp++) {
				Node nNode = nList.item(temp);
				Element eElement = (Element) nNode;
				serviceReceiver.add("service_receiver::" + eElement.getAttribute("android:name"));
			}

			results.addACTIVITYResults(activity);
			results.addFEATURESResults(features);
			results.addPERMISSIONResults(permissions);
			results.addINTENTSResults(intents);
			results.addSERVICERECEIVERResults(serviceReceiver);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Convenience method to get the last string for something like
	 * "com.wia.ucgepcdvlsl.activity.MainActivity"
	 *
	 * @param attribute
	 *            the string to split
	 * @return postSplit the last string
	 */
	private String getLastString(String attribute) {
		String postSplit = attribute;
		while (true) {
			if (postSplit.contains(".")) {
				postSplit = postSplit.split("\\.", 2)[1];
			} else {
				postSplit = "." + postSplit;
				break;
			}
		}
		return postSplit;
	}
}
