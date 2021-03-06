import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;

/**
 * Created by Nassim on 20/04/2017.
 */
@WebServlet(name = "Default")
public class Default extends HttpServlet {


    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String clientIp = request.getRemoteAddr();

        String[] selectedService = request.getParameterValues("serviceSelection");
        String[] selectedData = request.getParameterValues("eIDdataSelector");
        ArrayList<String> sd=new ArrayList<String>();

        for(String s :selectedData){  //stupid stuff to use a parser
            sd.add("\""+s+"\"");
        }
        String service = selectedService[0];
        String servicekey = null;

        System.out.println(service);
        System.out.println("Selected eID Data: "+ sd.toString());

        JSONObject jo = new JSONObject();
        JSONParser parser = new JSONParser();
        JSONArray eIDData= null;
        try {
            eIDData = (JSONArray)parser.parse(sd.toString());
        } catch (ParseException e) {
            e.printStackTrace();
        }
        MiddlewareComm comm = new MiddlewareComm();


        switch (service) {
            case "firstExample":
                servicekey = "default1";
                break;
            case "secondExample":
                servicekey = "default2";
                break;
        }

        Certificate cert = null;
        String sCert = null;
        try {
            cert = getCertFromKeyStore(servicekey);
            sCert = comm.certToString(cert);
        }
        catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        catch (Exception e) {
            e.printStackTrace();
        }


        jo.put("selectedData", eIDData);
        jo.put("domain","Default");
        jo.put("service",service);
        jo.put("cert",sCert);



        // System.out.println("cert: " +sCert);
        System.out.println(jo.toJSONString());

        comm.sendCert(clientIp,jo.toJSONString());



        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");


        PrintWriter writer = response.getWriter();
        writer.println("<!DOCTYPE html><html>");
        writer.println("<head>");
        writer.println("<meta charset=\"UTF-8\" />");
        writer.println("<Title>Default Service Providors Demo</Title>");
        writer.println("</head>");
        writer.println("<body>");

        writer.println("<h1>Sent request for "+selectedService[0]+" </h1>");
        writer.println("</body>");
        writer.println("</html>");



    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");


        try (PrintWriter writer = response.getWriter()) {
            String clientIp = request.getRemoteAddr();
            writer.println("<!DOCTYPE html><html>");
            writer.println("<head>");
            writer.println("<meta charset=\"UTF-8\" />");
            writer.println("<Title>Default Service Providors Demo</Title>");
            writer.println("</head>");
            writer.println("<body>");

            writer.println("<h1>These are the Default services.</h1>");
            writer.println("<h4>Please select a service.</h4>");
            writer.println("<Form method=\"post\">");
            writer.println("<input type=\"checkbox\" name=\"serviceSelection\" value=\"firstExample\">example 1<br>");
            writer.println("<input type=\"checkbox\" name=\"serviceSelection\" value=\"secondExample\">example 2<br>");
            writer.println("<br><br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"name\">Name<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"address\">Address<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"country\">Country<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"birth_date\">Birth Date<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"age\">Age<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"gender\">Gender<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"picture\">Picture<br>");
            writer.println("<input type=\"submit\" name=\"submit\" value=\"Submit\">");
            writer.println("</Form>");
            writer.println("</body>");
            writer.println("</html>");
        }
    }


    private KeyPair getKeyPairFromKeyStore(String service) throws Exception {

        ServletContext context = this.getServletContext();

        InputStream ins = context.getResourceAsStream("/WEB-INF/default.jks");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, "SICKS".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("SICKS".toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(service+"pk", keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate(service+" cert");
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    private Certificate getCertFromKeyStore(String service) throws Exception {
        ServletContext context = this.getServletContext();

        InputStream ins = context.getResourceAsStream("/WEB-INF/default.jks");
        //InputStream ins = new FileInputStream("/default.jks");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, "SICKS".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("SICKS".toCharArray());


        java.security.cert.Certificate cert = keyStore.getCertificate(service+" cert");

        return cert;
    }
}
