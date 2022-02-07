import router from '@ohos.router';

var numbs = 0;
var code = 0;
var inputVal = 0;
export default {
    data: {
        pincode: router.getParams().pinCode,
    },
    onInit() {
        code = router.getParams().pinCode;
    },
    onChange(e){ 
        inputVal = e.value; 
    }, 
    onConfirm() {
        numbs = numbs + 1;
        if(numbs < 3){
            console.info('click cancel numbs < 3 ');
            console.info('code: ' + code);
            console.info('inputVal: ' + inputVal);
            if(code == inputVal){
            console.info('click cancel code == inputVal');
            callNativeHandler("EVENT_INPUT", "0");
            }else{
            console.info('click cancel code != inputVal');
            }
        }else{
            console.info('click cancel numbs > 3 ');
            callNativeHandler("EVENT_CONFIRM", "1");
        }       
    },
    onCancel() {
        console.info('click cancel');
        callNativeHandler("EVENT_CONFIRM", "1");
    }
}