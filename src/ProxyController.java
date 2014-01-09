import java.net.ProxySelector;

/**
 * Created by a.zakordonets on 9-1-14.
 */
public class ProxyController {
    private ProxySelector defaultProxy ;
    public ProxyController(){
        defaultProxy = ProxySelector.getDefault();
    }

    public void enableProxy(String proxyHost, String proxyPort){
        MyProxySelector ps = null;
        try {
            ps = new MyProxySelector(ProxySelector.getDefault(),
                    proxyHost,Integer.parseInt(proxyPort));
        } catch (NumberFormatException e) {
            throw new NumberFormatException("Proxy Port was specified incorrectly. It should be a number");
        }
        ProxySelector.setDefault(ps);
    }

    public void disableProxy(){
        ProxySelector.setDefault(defaultProxy);
    }
}
