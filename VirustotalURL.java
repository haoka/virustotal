import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import me.vighnesh.api.virustotal.VirusTotalAPI;
import me.vighnesh.api.virustotal.dao.URLScanReport;

public class VirustotalURL {

    public static void main(String[] args) {
    	
        URL[] urls = new URL[500];
    	int itemcount = 0;
    	try{
    		FileReader fr = new FileReader("C://VirustotalURL//url.txt");
    		BufferedReader br = new BufferedReader(fr);
        
    		String line,tempstring;
    		while((line = br.readLine())!=null)
    		{
    			tempstring = line; 
        	
	        	String[] tempArray = new String[1];
	        	tempArray = tempstring.split(",");
	            
	        	urls[itemcount] = new URL(tempArray[0]);
	        	
	        	itemcount++;

    		}
    		fr.close();

	        VirusTotalAPI virusTotal = VirusTotalAPI.configure("4a2d6c8102f8a59ab987ff33302074027f6cc4ee99230b6cc3f84fbe11308ea6");
	        List<URLScanReport> urlReports = virusTotal.getURLsReport(urls);
	        
	        SimpleDateFormat sdFormat = new SimpleDateFormat("yyyyMMddHHmmss");
	        Date date = new Date();
	    	BufferedWriter fw = null;
	    	File file = new File("C://VirustotalURL//"+ sdFormat.format(date) +".txt");
	    	fw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file, true), "UTF-8"));

	        for(URLScanReport scanReport : urlReports){
	
	        	fw.append(scanReport.getUrl()+ "," +
	        			scanReport.getResponseCode()+ "," +
	        			scanReport.getResource() + "," +
	        			scanReport.getScanId() + "," +
	        			scanReport.getPermalink() + "," +
	        			scanReport.getScanDate()+ "," +
	        			scanReport.getPositives() + "," +
	        			scanReport.getTotal());
	        	fw.newLine();
	        }
        
	        fw.flush();
	        fw.close();
    	}
    	catch(IOException e){
    		System.out.println("File not found");
    	}    
    	
    }

}