import router from '@ohos.router'

export default {
    data: {
        message: router.getParams().targetPkgName,
    },
    onInit() {
        console.info('getParams: ' + router.getParams());
    },
    onConfirm() {
        console.info('click confirm');
        callNativeHandler("EVENT_CONFIRM", "0");
    },
    onCancel() {
        console.info('click cancel');
        callNativeHandler("EVENT_CANCEL", "1");
    }
}