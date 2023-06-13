import pandas as pd
import tensorflow as tf

# 读取csv文件
df = pd.read_csv('model/binary_classification_new.csv')

# 选取11个特征和Label
feature_last = ['Bwd_Packet_Length_Min','Subflow_Fwd_Bytes','Total_Length_of_Fwd_Packets','Fwd_Packet_Length_Mean','Bwd_Packet_Length_Std','Flow_Duration','Flow_IAT_Std','Init_Win_bytes_forward','Bwd_Packets/s',
                 'PSH_Flag_Count','Average_Packet_Size']
features = df[feature_last]
data_result = df['Label']
#dataset是df的前20行


dataset = pd.DataFrame(features.head(30), columns=feature_last)
dataset['Label'] = data_result


dataset.to_csv('model/binary_classification_new.csv', index=False)


# 加载保存的模型
reconstructed_model = tf.keras.models.load_model('Final_Model')

# 进行推断
inference_ds = tf.data.Dataset.from_tensor_slices(dict(dataset)).batch(1)
predictions = reconstructed_model.predict(inference_ds)



# 输出预测结果
class_names = ['Class1', 'Class2', 'Class3', 'Class4']
for prediction in predictions:
    predicted_class = class_names[prediction.argmax()]
    if predicted_class == 'Class1':
        print('受到攻击')
    else:
        print('未受到攻击')

