import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.*;


public class IOTFlowAPI {

    public static void main(String[] args) throws Exception {

        Connection con = null;
        ResultSet rs = null;

        PreparedStatement ps = null;
        String JDBC_DRIVER = "com.cloudera.impala.jdbc41.Driver";
        String CONNECTION_URL = "jdbc:impala://cdh1:21050/defalut;AuthMech=3;UID=hive;PWD=;UseSasl=0";

        String secr = "DtumxrMizBaxjEolyzlPalVgRPDSmFxY";
        String key = "App00352010";
        SimpleDateFormat df = new SimpleDateFormat("yyyyMM");
//        List<String> monthList = geneMonthList();//不传参数则跑历史所有数据
        List<String> monthList = geneMonthList(df.format(new Date()));
        List<String> vnoList = new ArrayList<>();

        try
        {
            Class.forName(JDBC_DRIVER);
            con = DriverManager.getConnection(CONNECTION_URL);
            ps = con.prepareStatement("select distinct substr(flowcardno,1,19) from ods.ods_esy_equipment_info_r " +
                    "where flowcardno is not null and flowcardno<>'' and LENGTH(flowcardno)>=19;");
            rs = ps.executeQuery();
            //查询KUDU，获取所有vno
            while (rs.next())
            {
                vnoList.add(rs.getString(1));
            }
            //分批次查询，最大查询量为50条/次
            for(String month:monthList) {
                int beginIndex = 0;
                int endIndex = 50;
                while (endIndex <= vnoList.size() && beginIndex < vnoList.size()) {
                    String vnos = "";
                    for (int i = beginIndex; i < endIndex; i++) {
                        if (vnos.equals("")) {
                            vnos = vnoList.get(i);
                        } else {
                            vnos = vnos.concat("," + vnoList.get(i));
                        }
                    }
                    JSONObject jsonObj = new JSONObject(getData(secr, key, vnos, month));
                    JSONArray jsonArr = (JSONArray) jsonObj.get("data");
                    //逐条插入KUDU
                    for (Object i : jsonArr) {
                        JSONObject job = (JSONObject) i;
                        if (!job.get("message").equals("智能卡号不存在")) {
                            Object cardId = "'" + job.get("vno") + "'";
                            Object mt = "'" + job.get("month") + "'";
                            Object flow = job.get("flow");

                            String sql = String.format("upsert into dm.dm_esy_iotflow values(%s,%s,%s,concat(cast(unix_timestamp() as string),'000'));", cardId, mt, flow);
                            ps = con.prepareStatement(sql);
                            ps.executeUpdate();
                        }
                    }
                    beginIndex += 50;
                    endIndex += 50;
                    if (endIndex >= vnoList.size()) {
                        endIndex = vnoList.size();
                    }
                }
            }
        } catch (Exception e)
        {
            e.printStackTrace();
        } finally
        {
            try {
                assert rs != null;
                rs.close();
                ps.close();
                con.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * API网关标准请求方式（传输内容需要加密、签名）
     */
    public static String getData(String  secr,String key,String vnos, String month) throws IOException {
        String secret = secr;// app对应的密钥，更换为APP自己的真实密钥
        String appKey = key; // app对应的Key，更换为APP自己的真实Key
        //        String url = "http://openapi.qa.tew.yrt-tech.com/api/v1/sim/status";
        String url = "http://api.yrt-tech.com/api/v1/sim/flow/month";
        String content = "";

        //参数
        Map<String, Object> params = new HashMap<>();
        params.put("vno", vnos);
        params.put("month", month);
        // 将参数转成json格式数据
        String json = toJSONString(params);//没有参数时，需要传空JSON"{}"
        System.out.println("请求JSON(原文): ");
        System.out.println(json);
        // aes加密
        byte[] ciphertext = encrypt(secret, json.getBytes(DEFAULT_CHARSET));
//        System.out.println("请求JSON(AES加密后): " + Arrays.toString(ciphertext));
        // 加密后，进行base64编码后http传输
        String ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertext);
//        System.out.println("请求JSON(AES加密后的base64): " + ciphertextBase64);

        // 请求头参数，头参数名称为小写
        Map<String, String> header = new HashMap<>();
        // app key
        header.put("yrt-app-key", appKey);
        // 当前时间的毫秒数
        header.put("yrt-timestamp", String.valueOf(System.currentTimeMillis()));

        // 1、 将请求头中除“yrt-signature”参数外，
        // 以“yrt-”开头的参数按照“key=value”的方式拼接字符串后放入签名集合中
        // 请求头参数统一为小写
        List<String> values = new ArrayList<>();
        for (Map.Entry<String, String> entry : header.entrySet()) {
            values.add(entry.getKey() + "=" + entry.getValue());
        }
        // 2、将发送给平台的JSON数据进行SHA256加密后放入签名集合中（没有key）
        // contentDigest用于签名
        String contentSha256 = sha256(ciphertextBase64);
//        System.out.println("参与签名的头参数: "+ header);
//        System.out.println("请求JSON(AES/base64)的SHA256值: " + contentSha256);
        values.add(contentSha256);// 发送给平台的数据，base64编码后的数据
        // 3、将APP的密钥放入签名集合中（没有key）
        values.add(secret);
        // 4、对签名集合按照字典排序
        Collections.sort(values);
        // 5、排序后的集合拼接成字符串后进行SHA256加密
        StringBuilder str = new StringBuilder();
        for (String s : values) {
            str.append(s);
        }
        System.out.println("签名前的字符串: " + str);
        //加密后的内容作为“yrt-signature”值放入请求头中
        header.put("yrt-signature", sha256(str.toString()));

//        System.out.println("签名后的SHA256值: " + sha256(str.toString()));


        // 创建http请求
        CloseableHttpClient httpClient = HttpClients.createDefault();
        CloseableHttpResponse response = null;
        String resultString = "";
        try {
            HttpPost httpPost = new HttpPost(url);

            for (Map.Entry<String, String> entry : header.entrySet()) {
                httpPost.addHeader(entry.getKey(), entry.getValue());
            }

            // base64编码后的字符串发送给平台
            httpPost.setEntity(new StringEntity(ciphertextBase64));
            response = httpClient.execute(httpPost);

            System.out.println("本次请求的ID："+response.getFirstHeader("yrt-request-id"));//本次请求的ID，可用于查日志

            //平台访问成功
            StatusLine m = response.getStatusLine();
            if (response.getStatusLine().getStatusCode() == 200) {
                // 接收响应数据
                resultString = EntityUtils.toString(response.getEntity(), DEFAULT_CHARSET);
//                System.out.println("平台返回内容(base64): " + resultString);
                // base64转字节
                byte[] responseCiphertext = Base64.getDecoder().decode(resultString.getBytes(DEFAULT_CHARSET));
                //                System.out.println("返回base64字节码: " + Arrays.toString(responseCiphertext));
                // 解密得到返回内容
                byte[] decrypt = decrypt(secret, responseCiphertext);
                //                System.out.println("base64解密后: " + Arrays.toString(decrypt));
                content = new String(decrypt, DEFAULT_CHARSET);

                System.out.println("返回JSON: ");
                System.out.println(content);
                System.out.println();
                //返回数据的code为0视为业务处理成功，否则视为业务处理失败
            }else{
                System.out.println("HTTP请求被拒绝：httpCode="+response.getStatusLine().getStatusCode());

                //只有产生了请求ID（yrt-request-id）的，请求被拒绝时，才会有此信息
                System.out.println("HTTP请求被拒绝：原因="+response.getFirstHeader("yrt-reject-reason"));
            }
        }
        catch (Exception e) {
            // 异常处理略
            e.printStackTrace();
        }
        finally {
            response.close();
        }
        return content;
    }

    /**
     * 转成json格式，这里采用的是jackson
     *
     * @param params
     * @return
     */
    private static String toJSONString(Map<String, Object> params) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(Include.NON_NULL);
        try {
            return mapper.writeValueAsString(params);
        }
        catch (JsonProcessingException e) {
            // 异常处理略
            e.printStackTrace();
        }
        return null;
    }

    private static final char[] HEXS = "0123456789abcdef".toCharArray();// 小写的
    /**
     * sha256算法举例
     *
     * @param str
     * @return 注意是小写的
     */
    public static String sha256(String str) {
        try {

            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

            messageDigest.update(str.getBytes(DEFAULT_CHARSET));

            byte[] data = messageDigest.digest();
            final int l = data.length;
            final char[] out = new char[l << 1];// 乘2
            // two characters form the hex value.
            for (int i = 0, j = 0; i < l; i++) {
                out[j++] = HEXS[(0xF0 & data[i]) >>> 4];
                out[j++] = HEXS[0x0F & data[i]];
            }
            return new String(out);
        }
        catch (NoSuchAlgorithmException e) {
            // 异常处理略
            e.printStackTrace();
        }
        return null;
    }

    private static final String TRANSFORMATION = "AES/CBC/NoPadding";// java的AES加密默认为：AES/CBC/PKCS5Padding，IV参数为密钥的前16位
    private static final String ALGORITHM = "AES";
    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
    private static final ZerosPaddingMode PADDING_MODE = new ZerosPaddingMode();// 填充方式，这里不使用Java默认的加密方式，主要是考虑到跨语言的加密问题

    /**
     * 字符串加密
     * @param secret 取前16位作为key，后16位作为iv参数值 (UTF-8)
     * @param content 明文字节
     * @return 密文字节
     */
    public static byte[] encrypt(String secret, byte[] content) throws RuntimeException {
        try {
            //如果不够16位，将会抛出异常
            String secretKey = secret.substring(0, 16);//前16位，AES key size 128 的密钥要求必须是16位的
            String iv = StringUtils.substring(secret, -16);//后16位
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);//算法/模式/填充，默认是AES/ECB/PKCS5Padding
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(secretKey.getBytes(DEFAULT_CHARSET), ALGORITHM),
                    new IvParameterSpec(iv.getBytes(DEFAULT_CHARSET), 0, 16));
            return cipher.doFinal(PADDING_MODE.encode(content, cipher.getBlockSize()));
        }
        catch (Exception e) {
            throw new RuntimeException("AES 加密失败", e);
        }
    }

    /**
     * 加密字符串 (UTF-8)
     * @param secret
     * @param content
     * @return
     * @throws RuntimeException
     */
    public static byte[] encryptFromString(String secret, String content) throws RuntimeException {
        return encrypt(secret, content.getBytes(DEFAULT_CHARSET));
    }

    /**
     * AES 解密（AES/CBC/NoPadding）手动进行PKCS7方式填充补位剔除
     * @param secret 取前16位作为key，后16位作为iv参数值 (UTF-8)
     * @param ciphertext 密文字节
     * @return 明文字节
     * @throws RuntimeException
     */
    public static byte[] decrypt(String secret, byte[] ciphertext) throws RuntimeException {
        try {
            //如果不够16位，将会抛出异常
            String secretKey = secret.substring(0, 16);//前16位
            String iv = StringUtils.substring(secret, -16);//后16位
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);//算法/模式/填充，默认是AES/ECB/PKCS5Padding
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(secretKey.getBytes(DEFAULT_CHARSET), ALGORITHM),
                    new IvParameterSpec(iv.getBytes(DEFAULT_CHARSET), 0, 16));
            return PADDING_MODE.decode(cipher.doFinal(ciphertext), cipher.getBlockSize());
        }
        catch (Exception e) {
            throw new RuntimeException("AES 解密失败", e);
        }
    }

    /**
     * 解密成字符串 (UTF-8)
     * @param secret
     * @param ciphertext
     * @return
     * @throws RuntimeException
     */
    public static String decryptToString(String secret, byte[] ciphertext) throws RuntimeException {
        return new String(decrypt(secret, ciphertext), DEFAULT_CHARSET);
    }

    /**
     * 补零方式
     */
    public static class ZerosPaddingMode {
        /**
         * 对数据用“0”,对应ASCII为空字符进行补位，返回已补位的数据
         * @param data
         * @param blockSize
         * @return
         */
        public byte[] encode(byte[] data, int blockSize) {

            int length = data.length;
            if (length % blockSize != 0) {
                length = length + (blockSize - (length % blockSize));
            }

            byte[] out = new byte[length];
            System.arraycopy(data, 0, out, 0, data.length);

            return out;
        }

        /**
         * 剔除“0”
         * @param data
         * @param blockSize
         * @return
         */
        public byte[] decode(byte[] data, int blockSize) {
            int index = data.length;
            while (index >= 0) {
                if (data[index - 1] != 0) {
                    break;
                }
                index --;
            }
            byte[] out = new byte[index];
            System.arraycopy(data, 0, out, 0, index);
            return out;
        }
    }

    /**
     * 获取日期数组
     * @param month 'yyyyMM格式'
     * @return
     */
    public static List<String> geneMonthList(String... month){
        List<String> monthList = new ArrayList<>();
        SimpleDateFormat df = new SimpleDateFormat("yyyyMM");
        if(month.length == 0) {
            Date sDate = new Date(1561910400000L);//设置开始时间 2019年07月
            Date eDate = new Date();// 设置为当前时间
            while (sDate.getTime() < eDate.getTime()) {
                Calendar c = Calendar.getInstance();
                c.setTime(sDate);
                monthList.add(df.format(c.getTime()));
                c.add(Calendar.MONTH, 1);
                sDate = c.getTime();
            }
        } else {
            Collections.addAll(monthList, month);
        }
        return monthList;
    }
}


          