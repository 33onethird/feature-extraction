package main;

import java.io.*;
import java.util.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class FeatureExtractor {

	public static void main(String[] args) {
		System.out.println("STARTET");
		File input= new File(args[0]);
		if(input.isFile()&&input.getName().endsWith(".apk")) {
			analyze(input);
		}
		if(input.isDirectory()) {
		    File[] fList = input.listFiles();
		    for (File file : fList) {
				if(file.isFile()&&file.getName().endsWith(".apk")) {
					analyze(file);
				}
		    }
		}
//		
		try {
//			Process proc = Runtime.getRuntime().exec("java -jar apktool.jar d "+apk);
//			proc.waitFor();
//		
//		System.out.println("FINISHED APKTOOL DECRYPTION");
//		
//	       

		}catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private static void analyze(File input) {
		
		System.out.println("Analyzing: "+input.getName());
		File outputdir= new File (input.getName().substring(0,input.getName().length()-4));
		File XMLManifest =new File(outputdir+"/AndroidManifest.xml");
		File smaliDir =new File(outputdir+"/smali");
		File featureFile =new File(outputdir+"/Features.txt");
		try {
			Process proc = Runtime.getRuntime().exec("java -jar apktool.jar d "+input);
			proc.waitFor();
			
		ManifestAnalyzer mAnalyzer = new ManifestAnalyzer(XMLManifest);
		SmaliAnalyzer sAnalyzer = new SmaliAnalyzer(smaliDir.getAbsolutePath());
		
      PrintWriter writer = new PrintWriter(featureFile, "UTF-8");
      write(mAnalyzer.getActivities(),writer);
      write(mAnalyzer.getPermissions(),writer);
      write(mAnalyzer.getFeatures(),writer);
      write(mAnalyzer.getIntents(),writer);
      write(mAnalyzer.getServiceReciever(),writer);
      write(sAnalyzer.getApiCall(),writer);
      write(sAnalyzer.getURL(),writer);
      write(sAnalyzer.getCalls(),writer);
      write(sAnalyzer.getRealPermissions(),writer);
      writer.close();
		
		}catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	private static void write(Set<String> lines, PrintWriter writer) {
        for(String line : lines){
        	writer.println(line);
        }
	}

}
