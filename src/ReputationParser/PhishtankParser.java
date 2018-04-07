package ReputationParser;
import java.io.File;
import java.util.HashSet;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
/**
 * The PhishtankParser specifically parses the phishtank.xml file for its URLs and IP addresses
 *
 * @author Philipp Adam
 */
public class PhishtankParser {
	private final String PHISHTANK ="ReputationDBs/phishtank.xml";
	
	public PhishtankParser(HashSet<String> urls) {
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder;
		try {
			dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(new File(PHISHTANK));
			doc.getDocumentElement().normalize();

			NodeList nList = doc.getElementsByTagName("entry");
			for (int temp = 0; temp < nList.getLength(); temp++) {
				Node nNode = nList.item(temp);
				Element eElement = (Element) nNode;
				urls.add( eElement.getElementsByTagName("url").item(0).getTextContent());
			}
			
			 nList = doc.getElementsByTagName("detail");
			for (int temp = 0; temp < nList.getLength(); temp++) {
				Node nNode = nList.item(temp);
				Element eElement = (Element) nNode;
				urls.add( eElement.getElementsByTagName("ip_address").item(0).getTextContent());
			}
			
		}catch(Exception e) {
			
			
		}
	}
}
