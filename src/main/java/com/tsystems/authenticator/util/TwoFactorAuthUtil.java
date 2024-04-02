package com.tsystems.authenticator.util;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class TwoFactorAuthUtil {

    //@Autowired
    //private ParameterStubV1 parameterStubV1;

    /**
     * 生成二维码内容    网站地址（可不写）
     *
     * @return
     */
    public static String getQrCodeText(String secretKey, String account, String issuer) {
        String normalizedBase32Key = secretKey.replace(" ", "").toUpperCase();
        try {
            String Url = null;
            Url = "otpauth://totp/"
                    + URLEncoder.encode((!StringUtils.isEmpty(issuer) ? (issuer + ":") : "") + account, "UTF-8").replace("+", "%20")
                    + "?secret=" + URLEncoder.encode(normalizedBase32Key, "UTF-8").replace("+", "%20")
                    + (!StringUtils.isEmpty(issuer) ? ("&issuer=" + URLEncoder.encode(issuer, "UTF-8").replace("+", "%20")) : "");
            //log.info(Url);
            return Url;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * description:
     *
     * @author 获取二维码
     */
    public static String getQrCode(String loginName, String newSecretKey) {
        String base64Image = null;
        // 生成二维码内容
        String qrCodeText = getQrCodeText(newSecretKey, loginName, "VGC DATA BANK");
        int width = 300; // 图片宽度
        int height = 300; // 图片高度
        try {
            // 将URL转换为BitMatrix
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(qrCodeText, BarcodeFormat.QR_CODE, width, height);
            // 将BitMatrix转换为BufferedImage
            BufferedImage bufferedImage = MatrixToImageWriter.toBufferedImage(bitMatrix);
            // 保存二维码图片到本地文件
            //File file = new File("D:\\图片\\qrcode.png");
            //ImageIO.write(bufferedImage, format, file);
            //log.info("QR Code image generated successfully!");

            // 生成二维码图像
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "png", outputStream);

            // 获取图像的字节数组，并使用 Base64 编码转换成字符串
            byte[] imageData = outputStream.toByteArray();
            //base64Image = AppConfigUtil.getStringValue(TwoFactorAuthConstant.MICROSOFT_AUTH_BASE64_IMAGE) + java.util.Base64.getEncoder().encodeToString(imageData);
            base64Image = Base64.encodeBase64String(imageData);
            return base64Image;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}
